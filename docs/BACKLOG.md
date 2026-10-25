# Backlog

Ideas and known gaps that are deliberately not in v0.1. Each line says why it was deferred. Items marked **gap** are shortcomings of the current code that the docs describe rather than hide; the others are features.

## Security gaps

- **Authenticate the grants table (gap).** Grants are plain rows in `vault.db`; a process that can write the file can insert one and release secrets with no prompt (THREAT-MODEL 4.5). Fix: add a MAC column keyed from the vault key (`Vault.DeriveKey("grant-mac")`) and refuse rows that don't verify. Deferred because it changes the schema and needs a migration for existing grants; it is the highest-value follow-up.
- **Cross-check grants against the audit log (gap).** An `allowed_grant` row whose grant ID has no earlier `allowed_new_grant` row is a forged or stale grant. `audit verify` could report it. Deferred; detection only, and the MAC above makes it mostly moot.
- **Audit external anchor.** Periodically publish or sign the chain head (to a file outside the vault, a remote, the Keychain) so truncation of the newest rows is detectable. Deferred: needs a place to anchor that the vault-file attacker can't also write, which is a product decision.
- **Presence-gate `set`, `delete`, overwrite and `grants revoke` (gap).** Today a same-user process can destroy or replace secrets and drop grants (DoS and integrity, not disclosure). Gating them needs an approval flow with its own prompt text and an exemption for first-time `set` by the human. Deferred to keep v0.1's surface small; recorded in the threat model.
- **User-level policy the repo can't override.** Policy lookup uses the nearest `.grantd.yml`, so an agent that can write files can shadow a stricter parent. A policy kept outside the repo (or intersected with it) would remove that. Deferred: it changes the policy model.
- **Show the policy file path and the grant's real scope in the dialog.** "Allow for N" scopes the grant to the policy's command prefix, which can be much broader than the command shown. Deferred; the dialog text is already near its length budget.
- **Bind the vault key to user presence or to a stronger code identity.** The Secure Enclave key has no user-presence flag by design (the daemon must unwrap it unattended), and an ad-hoc signature is a weak identity. Options: Developer ID plus a provisioning profile so the keychain access group is tied to a team ID; a presence-gated unwrap with a prompt at daemon start. Deferred: needs signing infrastructure and a decision about unattended start.
- **Hardened runtime for the signed binary.** `make sign` does not set `--options runtime`. Deferred with the signing work.
- **MinTier binding for `Get`/`List` metadata.** `min_tier` is bound into the GCM data and verified when a secret is decrypted for a release, but `list` and `Vault.Get` return the column unverified. Binding it (for example a metadata MAC) would make displayed tiers trustworthy. Deferred: displayed value only; releases already verify.
- **Authenticate secret metadata.** `expires_at`, `url`, `notes` and tags are not covered by the GCM tag, so a file-write attacker can extend an expiry. Same MAC idea as above.
- **Per-secret `--min-tier none`.** `set --min-tier none` currently means "vault default", and `TierNone` can never be stored on a real vault, on purpose. A deliberately unprotected secret (for example a non-sensitive token an agent may use after a plain dialog) would need an explicit opt-in. Deferred: the conservative choice was to disallow it.
- **Process sandboxing and network egress control for approved commands** (HANDOFF §2, "v2 candidate"). The approved-command-exfiltrates hole can't be closed by approval alone. Deferred: large, platform-specific.
- **Redact common encodings** (base64, hex, URL-encoded forms of each value) as extra defence in depth. Never complete; deferred because it adds false positives and would suggest a guarantee that doesn't exist.

## Behaviour and usability

- **Atomic import over the socket.** `vault.Import` is transactional, but `grantd import` sends one `set` per key, so a daemon error midway can leave a partial import. Needs an `import` op. Deferred: the CLI pre-checks names and conflicts, which covers the usual failure.
- **Relay signals beyond INT/TERM.** `grantd run` turns SIGINT/SIGTERM into a closed connection, which makes the daemon stop the command's process group (SIGTERM, then SIGKILL after 2 seconds). SIGHUP, SIGUSR1, SIGWINCH and others are not forwarded. Needs a signal frame in the protocol and an authorisation story. Deferred.
- **Child environment and `PATH` for the launchd service.** The child runs with the daemon's environment; under `grantd service install` that is launchd's minimal one, so `/opt/homebrew/bin` tools aren't found. Options: write a `PATH` into the plist, or let the client pass an allow-listed `PATH` (with the caveat that an agent then controls it). Deferred pending a decision about who may influence the child's environment.
- **`--keychain-fallback` for the MCP auto-started daemon.** The flag exists on `init`, `daemon` and `service install`, but `grantd mcp` starts a plain `grantd daemon`, so a vault created with the fallback needs the daemon (or service) started by hand. Deferred: needs the shim to know how the vault was created.
- **Auto-started daemon environment.** The MCP shim forwards a short allow-list of variables and drops `GRANTD_HOME`, and the daemon's output goes to `/dev/null`. Add a log file for it. (MCP log file for the auto-started daemon.)
- **Configurable "Allow for N".** The default is 1 hour and only `max_grant_ttl` can lower it; HANDOFF §6 calls it configurable. Deferred: needs UI for choosing a duration.
- **Use-limited grants ("Allow N times").** `uses_remaining` is implemented in the grant store and protocol, but nothing creates such a grant. Deferred: needs a button or policy key.
- **Purge expired grants.** `grant.Store.Purge` exists but is never called; expired rows stay in the table (they are ignored). Trivial; deferred.
- **NSAlert-based chooser instead of `osascript`.** A native alert from the daemon (or a helper app) would avoid `osascript` and give control over the layout and the default button. Deferred: needs an app bundle for a proper UI process.
- **Interactive input for the child.** The child's stdin is `/dev/null`. Deferred.
- **Audit export over the socket is capped at 1 MiB**; larger logs need `audit list --limit` or paging. Deferred.
- **Windows-specific code paths** (`policy` ownership check, process groups, named-pipe transport) are stubs. Part of the Windows backend.

## Platforms

- **Linux (v0.2).** Secret Service (libsecret) key store with an optional TPM2 and an Argon2id passphrase file as the last resort; a native dialog approver (`TierDialog`); systemd `--user` unit. The seams (`keystore.KeyStore`, `approve.Approver`, `service.Manager`) already exist and the peer-credential check has a `SO_PEERCRED` implementation.
- **Windows (v0.3).** DPAPI (optionally CNG/TPM) key store, Windows Hello `UserConsentVerifier` approver, `go-winio` named pipe with a current-user ACL, a startup task.
- **Socket forwarding guide (v0.4).** How to expose the daemon to devcontainers, WSL and SSH sessions without weakening the peer check.
