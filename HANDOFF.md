# grantd — local secrets broker for AI coding agents

> This is the original v0.1 design brief, kept for history. It is not kept up to date: the current documentation is in [docs/](docs/README.md).

Handoff for the implementing agent. Read fully before writing code. Decisions below are made; don't reopen them unless you hit a hard blocker, and then say so explicitly rather than silently deviating.

(Project name is a placeholder — rename freely, keep the structure.)

---

## 1. What this is

A single-binary, open-source (Apache-2.0), **local-only** daemon that lets AI coding agents (Claude Code, Codex, Cursor, anything with a shell) run commands that need secrets **without the agent ever receiving a plaintext secret**, and without any secret release happening without a human approving it.

Core loop:

1. Agent runs `grantd run --secrets API_KEY,DB_URL -- php artisan sync`
2. CLI sends request to the daemon over a local socket.
3. Daemon checks policy, then either matches an existing grant or shows a native approval prompt to the human: *"claude-code wants to run `php artisan sync` with API_KEY, DB_URL in ~/projects/foo — Allow once / Allow 1h / Deny"*.
4. On approval, daemon spawns the command with secrets injected as env vars, streams redacted stdout/stderr back, returns exit code.
5. Everything is written to an append-only audit log.

There is **no code path** that returns a plaintext secret to a caller. Not CLI, not MCP, not socket. The only place a human sees a value is a dedicated interactive `grantd show KEY` that itself requires presence approval and prints to a TTY only.

## 2. Non-goals (v1)

- No cloud sync, no multi-device, no accounts, no server mode.
- No GUI vault app. CLI + native OS prompt only.
- No process sandboxing / network egress control (v2 candidate).
- No secret rotation, no dynamic secrets.
- No Windows or Linux in v0.1 — but interfaces are defined so they slot in without touching core.

## 3. Threat model (be honest in the README)

**Protects against**
- Secrets landing in agent context, chat history, vendor logs.
- Accidental `cat .env` / `printenv` exposure — there is no plaintext on disk and no env var outside the child process.
- Silent secret use — every release is visible and approved.
- Prompt-injected "fetch the key and send it to X" — there is no fetch.

**Does NOT protect against**
- An approved command that itself exfiltrates (`deploy.sh` curling the key out). Mitigation is the human seeing the exact command at approval + command-prefix policy. Say this plainly.
- A compromised user account with hardware-presence bypass.
- Redaction misses: exact-match redaction only. Encoded/partial secrets in output get through. Document it.

The one real security boundary is **user presence at release time**. Everything else is defense in depth.

## 4. Architecture

```
┌──────────────┐  socket   ┌───────────────────────────────┐
│ grantd CLI   │──────────▶│ grantd daemon (user-level)     │
│ (agent calls)│◀──────────│  policy → grants → approver    │
└──────────────┘           │  → keystore → spawn → redact   │
┌──────────────┐           │  → audit                       │
│ MCP shim     │──────────▶│                                │
└──────────────┘           └───────────────┬───────────────┘
                                           │ platform backends
                              ┌────────────┴─────────────┐
                              │ KeyStore   │  Approver   │
                              │ (mac/win/  │ (TouchID /  │
                              │  linux)    │ Hello / dlg)│
                              └────────────┴─────────────┘
```

- Daemon runs as the user, never root. launchd agent (mac) / systemd user unit (linux) / startup task (win).
- Vault: SQLite file at `$XDG_DATA_HOME/grantd/vault.db` (mac: `~/Library/Application Support/grantd/`), mode 0600. Values encrypted AES-256-GCM with a per-vault data key. The data key is wrapped by the platform KeyStore — **the data key is never on disk in plaintext, never in an env var, never in a config file.**
- Language: Go. One module. cgo only where unavoidable (mac Keychain/LocalAuthentication; libsecret on linux). Windows via `golang.org/x/sys/windows` + WinRT bindings, no C.

## 5. Platform seams — define these in the first commit

```go
// Wraps/unwraps the vault data key using OS-protected storage.
type KeyStore interface {
    Wrap(ctx context.Context, dataKey []byte) ([]byte, error)
    Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
    Tier() PresenceTier // what unwrap requires
}

// Asks the human. Must be impossible to satisfy from the agent's shell.
type Approver interface {
    Ask(ctx context.Context, req ApprovalRequest) (Decision, error)
    Tier() PresenceTier
}

type PresenceTier int
const (
    TierNone     PresenceTier = iota // headless / pre-grant only
    TierDialog                       // OS dialog, no biometric (linux default)
    TierHardware                     // Touch ID / Windows Hello / TPM-gated
)
```

Backends:

| | KeyStore | Approver | Tier |
|---|---|---|---|
| macOS | Keychain item + Secure Enclave wrapping via Security.framework | LocalAuthentication.framework (Touch ID → password fallback) | Hardware |
| Windows | DPAPI (`CryptProtectData`, user scope), optionally CNG/TPM | Windows Hello `UserConsentVerifier` | Hardware |
| Linux | Secret Service (libsecret) → TPM2 optional → Argon2id passphrase file (last resort) | Native dialog (own GTK window; `zenity`/`kdialog` acceptable for v0.2) | Dialog |

Policy can require a minimum tier per secret. A request that can't meet it is **refused**, never downgraded.

Socket: Unix domain socket with peer-cred check (`SO_PEERCRED` / `LOCAL_PEERCRED`) — only same UID. Windows: named pipe via `go-winio` with current-user-only ACL.

## 6. Data model

**Secret**
- `name` (string, `[A-Za-z0-9_/.-]+`, namespaced with `/` e.g. `aws/access_key`)
- `ciphertext`, `nonce`
- `tags []string`, `url`, `notes`, `expires_at`
- `min_tier` (default: Hardware on mac/win, Dialog on linux)
- `created_at`, `updated_at`

**Grant** — the unit that makes this usable
- `caller` (string: `claude-code`, `codex`, `cli`, … taken from `--caller` or MCP client name; informational, not trusted)
- `cwd_prefix` (absolute path; request cwd must be under it)
- `secrets []glob` (e.g. `aws/*`)
- `cmd_prefix []string` (e.g. `["php","artisan"]`) — request argv must start with it
- `expires_at`
- `uses_remaining` (nil = unlimited within TTL)

Grant matching: a request matches if caller, cwd, every requested secret, and argv prefix all satisfy a non-expired grant. Otherwise → Approver. The approval prompt offers: *Allow once*, *Allow for N* (1h default, configurable), *Deny*. "Allow for N" creates a grant scoped to exactly this (caller, cwd, secret set, argv prefix).

**Policy** — per repo, committed: `.grantd.yml` in cwd or nearest ancestor
```yaml
version: 1
secrets:            # what this repo may request at all
  - aws/*
  - DB_URL
commands:           # allowed argv prefixes
  - [php, artisan]
  - [aws]
  - [./deploy.sh]
max_grant_ttl: 4h
```
No policy file → every request requires explicit approval, and the prompt says "no policy". Policy restricts; it never grants.

**Audit** — SQLite table, append-only, HMAC-chained (each row includes HMAC of previous row + content, key derived from data key). Fields: ts, caller, cwd, argv, secrets requested, decision, grant_id, exit_code, duration. `grantd audit verify` checks the chain.

## 7. Wire protocol (daemon socket)

Newline-delimited JSON, one request/response per connection, with a streaming frame for command output.

```jsonc
// request
{"v":1,"op":"run","caller":"claude-code","cwd":"/abs/path","argv":["php","artisan","sync"],
 "secrets":["API_KEY","aws/*"],"env_prefix":"","timeout_s":600}

// stream frames (0..n)
{"stream":"stdout","data":"...redacted..."}
{"stream":"stderr","data":"..."}

// final
{"ok":true,"exit_code":0,"grant_id":"...","audit_id":"..."}
{"ok":false,"error":"denied","reason":"user_denied"}
```

Other ops: `list` (names + metadata, no values), `exists`, `masked` (`****WXYZ`, last 4 only, min length 12 else fully masked), `set` (value read from stdin by CLI, sent over socket — allowed, this is the human putting a secret in), `delete`, `show` (TTY-only, presence-gated, never via MCP), `grants` (list/revoke), `audit`, `status`.

## 8. CLI surface

```
grantd init                      # create vault, wrap data key in KeyStore
grantd set NAME [--tags ..] [--url ..] [--expires 30d] [--min-tier hardware]   # value from stdin or hidden prompt
grantd list [--tag x] [--expiring 7d]
grantd masked NAME
grantd delete NAME
grantd show NAME                 # presence-gated, TTY only, refuses if not a TTY
grantd run --secrets A,b/* [--caller x] [--env-prefix APP_] [--timeout 10m] -- cmd args…
grantd grants [list|revoke ID|revoke --all]
grantd audit [list|verify|export --csv]
grantd import .env [--dry-run] [--on-conflict skip|overwrite|error]
grantd daemon                    # foreground
grantd service [install|uninstall|status]   # launchd / systemd --user / win task
grantd mcp                       # stdio MCP server, thin shim over the socket
grantd status
```

`run` semantics: secrets become env vars named by the last path segment uppercased (`aws/access_key` → `ACCESS_KEY`), or full name with `/`→`_` if collision, with optional `--env-prefix`. Child gets a clean copy of the parent env + injected vars. Output redacted: exact match of every injected value → `[REDACTED:NAME]`. Also redact in the daemon's own error messages.

## 9. MCP server

Tools exposed (names fixed):
- `secret_list`, `secret_exists`, `secret_masked`
- `secret_run` — args: `argv[]`, `secrets[]`, `cwd?`, `timeout_s?`. Returns `{exit_code, stdout, stderr, grant_id}`.

**Deliberately absent:** any tool returning a value. Do not add one "for convenience".

MCP shim passes the MCP client name as `caller`. Document Claude Code config:
```json
{"mcpServers":{"grantd":{"command":"grantd","args":["mcp"]}}}
```
No password, no env vars in that config. If the daemon isn't running, the shim starts it (user-level) or returns a clear error.

## 10. Repo layout

```
cmd/grantd/            main, cobra commands
internal/daemon/       socket server, request router
internal/vault/        sqlite, aes-gcm, data key lifecycle
internal/policy/       .grantd.yml loader + matcher
internal/grant/        grant store + matcher
internal/approve/      Approver interface + ApprovalRequest
internal/approve/darwin/   LocalAuthentication (cgo)
internal/approve/windows/  Hello
internal/approve/linux/    dialog
internal/keystore/     KeyStore interface
internal/keystore/darwin|windows|linux/
internal/runner/       spawn, env injection, redacting writer
internal/audit/        hmac chain
internal/proto/        wire types
internal/mcp/          stdio server over socket
docs/                  README, THREAT-MODEL.md, PROTOCOL.md
```

## 11. Milestones

**v0.1 — macOS, usable by me daily**
1. Module, layout, interfaces, proto types, `make` targets, CI (go test, vet, staticcheck). Stub KeyStore/Approver with a `TierNone` "dev" backend behind a build tag so core is testable headless.
2. Vault + `init/set/list/masked/delete/import`.
3. Daemon + socket + peer-cred + `status`.
4. `run` end-to-end with dev approver (auto-allow in tests), redaction, exit codes, timeouts, signals forwarded to child.
5. Policy loader + grant store + matching. Tests for every matcher edge (cwd prefix traversal, glob, argv prefix, expiry).
6. Audit chain + `verify`.
7. macOS KeyStore (Keychain + Secure Enclave) and Approver (LocalAuthentication). Manual test checklist in docs.
8. `service install` for launchd.
9. MCP shim. Test with Claude Code.
10. README + THREAT-MODEL.md written for a skeptical security engineer.

**v0.2 — Linux** (Secret Service + GTK dialog, TPM optional), **v0.3 — Windows**, **v0.4 — socket forwarding guide for devcontainers/WSL/SSH**.

## 12. Definition of done (v0.1)

- `go test ./...` green, race detector clean, >80% coverage on vault/policy/grant/runner/audit.
- `grep -r` across the tree for any path where a secret value is logged, printed, or returned over the socket outside `show` — must be none. Add a test that asserts `run` responses never contain an injected value.
- Fresh-machine install → `init` → `set` → `run` via Claude Code → Touch ID prompt → redacted output, in under 5 minutes following README only.
- Daemon survives reboot; vault unreadable without the KeyStore.

## 13. Working rules for you

- Don't invent APIs. If unsure whether a framework call or Go package exists, check docs or say so.
- Small commits, one milestone step each, conventional commit messages.
- Write the test before the backend when the backend needs hardware you can't exercise in CI.
- Don't add features outside this doc. Note ideas in `docs/BACKLOG.md` instead.
- When blocked on a product decision, make the conservative (more restrictive) choice, implement it, and flag it at the top of your report. Don't stop to ask for things that can be changed in a follow-up commit.
- Report back with: what's done against §11, what's flagged, exact commands to try it.
