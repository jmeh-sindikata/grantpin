# grantd

grantd is a local secrets broker for AI coding agents. It lets an agent (Claude Code, Codex, Cursor, anything with a shell or MCP) run a command that needs credentials without the agent ever receiving the credential, and without any release happening unless a human approves it at that moment. You store secrets once in an encrypted vault. The agent asks for "run this command with these secret names". A background daemon shows you the exact command in a native macOS dialog, then a Touch ID prompt. If you approve, the daemon starts the command with the secrets in its environment, returns the output with every injected value replaced by `[REDACTED:NAME]`, and writes an audit record. There is no operation that returns a secret to the agent; the only way a human sees a value is `grantd show`, which is presence-gated and prints to a terminal.

It is a single Go binary, Apache-2.0, local only (no cloud, no accounts). v0.1 supports macOS only.

## Architecture

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

Only the macOS backends exist today (Secure Enclave or Keychain for the key store, an `osascript` dialog plus LocalAuthentication for the approver). The CLI and the MCP shim are thin clients: policy, grants, prompts, redaction and audit all happen inside the daemon.

## What this protects against, and what it does not

The full analysis is in [THREAT-MODEL.md](THREAT-MODEL.md). The short version:

**It protects against**

- Secrets landing in the agent's context, chat history, or the vendor's logs. No tool, CLI verb or socket op returns a value to the agent (except `show`, below).
- `cat .env` / `printenv` exposure. There is no plaintext secret on disk and none in your shell's environment; the value exists in the environment of the one approved child process.
- Silent use. Every release needs either a fresh approval or a grant that you created by approving; every release is audited. Grants are stored with an HMAC under a key derived from the vault key, so a row someone inserts or edits in the vault file never matches (it is listed as `TAMPERED` by `grantd grants` and `grantd status` prints a warning).
- "Fetch the key and send it to X" prompt injection. There is nothing to fetch. The injected agent can only ask to run a command, and you see the command.

**It does not protect against**

- **An approved command that exfiltrates.** If you approve `./deploy.sh` and that script sends the key elsewhere, grantd cannot tell. You are the control: read the command in the dialog.
- **Code that already runs as you with full control of your account.** Presence is enforced by the daemon's logic, not by cryptography on the key. Forged grant rows are rejected, but a process running as you can still delete the vault, replace the `grantd` binary or the launchd plist, write `.grantd.yml` files, replay a previously captured genuine grant row within its lifetime, or (with the Keychain fallback) read the key. grantd is a defence for the agent-with-a-shell case where you are watching prompts, not for an attacker who owns your user account.
- **Redaction misses.** Redaction is exact byte match of the injected value. Base64, hex, URL-encoding, substrings, hashes and reversed output pass through unchanged.
- **A compromised account or a fallback key store.** With a vault created by `grantd init --keychain-fallback` the vault key is readable by anything running as you. With the Secure Enclave key there is no per-use Touch ID on the key (by design); see the threat model for what that means.
- **Secrets set, overwritten or deleted by the agent.** `set`, `delete` and overwrite are not presence-gated. A same-user process can destroy or replace a secret (a denial-of-service and integrity risk, not a disclosure).

The one real security boundary is **human presence at release time**: the dialog that shows the exact command, and the Touch ID prompt behind it. Everything else is defence in depth.

## Install

Requirements: macOS, Go 1.27 or newer (`go.mod` says `go 1.27.3`), and the Xcode command line tools. The Touch ID approver and the Secure Enclave/Keychain code use cgo, so build with `CGO_ENABLED=1` (the default when a C compiler is present); a build without cgo compiles but `grantd init` and `grantd daemon` report that the macOS backends need cgo.

```sh
git clone <this repository> grantd && cd grantd
export PATH=/opt/homebrew/bin:$PATH      # if Go is a Homebrew install
make build                               # writes bin/grantd (production build)
make sign                                # optional; ad-hoc signs bin/grantd, but does not unlock the Secure Enclave (see below)
install -m 0755 bin/grantd ~/.local/bin/grantd   # or any permanent directory on PATH
```

`make build` produces a production binary: the insecure test backends are not compiled in (see [Development](#development)).

**`make sign` does not help today.** On macOS, Secure Enclave keys live in the data-protection keychain, which the system opens only to code with an accepted keychain access group. A plain `go build` binary has none, and `make sign` (ad-hoc signature, `build/grantd.entitlements`, identifier `dev.grantd.grantd`, entitlement `com.apple.application-identifier`) was tested on macOS 27.0.1 and is not accepted either: key creation still fails with `errSecMissingEntitlement` (`-34018`). That is outcome D in [MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md) §2a. The Secure Enclave needs a real Apple Development or Developer ID identity with a provisioning profile, i.e. a signed app bundle, which is planned for v0.2. The target stays in the Makefile for a build you sign yourself, but do not expect it to unlock the Secure Enclave.

**For a from-source build on current macOS, create the vault with `grantd init --keychain-fallback`** (next section). Plain `grantd init` is the path for a properly signed build, where the Secure Enclave is available.

**Signed bundle (restores the Secure Enclave).** With a paid Apple Developer account you can wrap the same binary in a Developer ID signed `.app` whose provisioning profile carries `keychain-access-groups`; the daemon inside the bundle can then create the Secure Enclave key (`keystore tier: hardware`). `make bundle` assembles `dist/grantd.app`, `make sign-bundle IDENTITY=... PROFILE=... TEAM_ID=...` signs it, and `grantd service install --exe dist/grantd.app/Contents/MacOS/grantd` (or `--exe /Applications/grantd.app`) runs the daemon from it. It has no UI yet, and the signing steps have not been run end to end; the portal setup and the exact commands are in [MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md) §2c.

**Run the daemon at login:**

```sh
grantd service install        # writes ~/Library/LaunchAgents/dev.grantd.daemon.plist and starts it
grantd service status
```

The service is a per-user LaunchAgent (never root) that runs `grantd daemon`, restarts it if it exits with an error, and logs to `~/Library/Logs/grantd/`. It starts at login in your GUI session, not at boot, because the prompts need a desktop session and the Secure Enclave key is only usable while the Mac is unlocked. `service install` refuses a binary under a temporary directory; install `grantd` to a permanent location first. To remove it: `grantd service uninstall`.

If you would rather not install a service, run `grantd daemon` in a spare terminal, or let `grantd mcp` start the daemon for you the first time it is needed (see [MCP server](#mcp-server)).

## Quick start

This is the whole path from a built binary to a Touch ID-gated run through Claude Code. It assumes `grantd` is on your `PATH` and you have a project directory, here `~/projects/demo`.

**1. Create the vault.**

```sh
grantd init --keychain-fallback
# vault created at /Users/you/Library/Application Support/grantd/vault.db (keystore tier: dialog)
```

Use `--keychain-fallback` for a build you made from source: on current macOS an unsigned or ad-hoc signed binary cannot create a Secure Enclave key (`-34018`, see [MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md) §2a), and `make sign` does not change that. What the flag changes:

- The keystore tier is `dialog`, not `hardware`.
- New secrets default to the `dialog` tier, because `init` gives them the key store's tier.
- Touch ID still gates every release: the approver is still `hardware`.
- The vault key is wrapped by a random key held in a login-keychain item, not by a key in the Secure Enclave, so it is readable by processes running as you. See [Presence tiers](#presence-tiers-and-the-keychain-fallback) and the threat model.

The choice is recorded in the vault, so no later command needs the flag. `init` does not need the daemon; it creates the SQLite vault (mode 0600).

For a properly signed build (Apple Development or Developer ID identity with a provisioning profile), run plain `grantd init` instead:

```sh
grantd init
# vault created at /Users/you/Library/Application Support/grantd/vault.db (keystore tier: hardware)
```

This creates a Secure Enclave key, wraps a random 256-bit vault key with it, and new secrets default to `hardware`. If it fails with a Secure Enclave error, use the fallback above.

**2. Make sure the daemon is running.** If you have not installed the service yet:

```sh
grantd service install
grantd status
# daemon:       running (pid 4242)
# ...
# keystore:     dialog        (hardware with a Secure Enclave vault)
# approver:     hardware
```

**3. Store a secret.** The value is read from a hidden prompt, or from stdin; it is never an argument.

```sh
grantd set API_KEY                      # type the value, input hidden
# or: printf %s "$VALUE" | grantd set API_KEY
# stored API_KEY
grantd list
# NAME     TIER      EXPIRES  TAGS  URL
# API_KEY  dialog    -        -     -
```

Names are `[A-Za-z0-9_/.-]+`, with `/` for namespaces (`aws/access_key`). Inside the command the secret becomes an environment variable named after the last path segment, uppercased (`aws/access_key` becomes `ACCESS_KEY`).

**4. Add a policy to the project** (optional but recommended). Create `~/projects/demo/.grantd.yml`:

```yaml
version: 1
secrets:            # what this repo may ever request
  - API_KEY
commands:           # argv prefixes this repo may run with secrets
  - [printenv]
max_grant_ttl: 1h   # cap on "Allow for N"
```

A policy only restricts; it never approves anything. Without one the prompt carries the words "(no policy)" and any command may be requested. See [Policy files](#policy-files).

**5. Tell Claude Code about grantd.** From a shell:

```sh
claude mcp add grantd -- grantd mcp
```

or put this in the project's MCP configuration (`.mcp.json` in the project root for a project-scoped server). There is deliberately no password and no environment variable in it:

```json
{"mcpServers":{"grantd":{"command":"grantd","args":["mcp"]}}}
```

`grantd` must be on the `PATH` that Claude Code sees; otherwise use an absolute path for `command`. Start `claude` in `~/projects/demo`; `/mcp` should list `grantd` with four tools: `secret_list`, `secret_exists`, `secret_masked`, `secret_run`.

**6. Ask the agent to use it.** For example: *"Using grantd, run `printenv API_KEY` with the API_KEY secret."* The agent calls `secret_run`.

**7. Approve.** Two prompts appear, in this order.

First an `osascript` dialog titled **grantd** with a caution icon:

```
An agent is asking grantd to release secrets:

claude-code wants to run `printenv API_KEY` with API_KEY in /Users/you/projects/demo

Allow for 1h covers: printenv … in /Users/you/projects/demo and subfolders.

[ Deny ]   [ Allow once ]   [ Allow for 1h ]
```

Deny is the default button and also what Esc, closing the dialog, or 120 seconds of silence mean. If the project had no policy, the text ends with "(no policy)". If the request names a glob, the dialog lists what it matched, for example `aws/* (aws/access_key, aws/secret_key)`. The caller name is whatever the MCP client reported in its handshake (lowercased and sanitised); it is informational, not proof of who is asking. The line starting "Allow for 1h covers:" states exactly what the grant will permit if you press the third button: the command prefix (here the policy's `printenv`; without a policy, the whole command), the directory and everything beneath it, for that long, for the same caller and secrets. Read the command and that scope; they are the control.

The duration on the third button is the policy's `max_grant_ttl` (so `8h` with `max_grant_ttl: 8h`), but never more than 24 hours, and 1 hour when there is no policy. Two other prompts look different on purpose: `grantd show` offers only `[ Deny ] [ Reveal once ]` (never a duration), and `grantd grants add` shows "Create a standing grant?" with `[ Cancel ] [ Create standing grant ]` (see [Standing grants](#standing-grants)). Only this release prompt can offer "Allow for N".

Then, only if you pressed an Allow button, the macOS authentication sheet (Touch ID, or your account password if there is no sensor or Touch ID is locked out) repeats the request. Touch the sensor. Only the button and a successful authentication together release the secret. Cancelling the sheet is a deny.

"Allow for 1h" stores a grant: for the next hour, the same caller, working directory (and anything beneath it), secrets and command prefix run without a prompt, as the "covers:" line said. "Allow once" stores nothing.

**8. What the agent sees.** The tool result is:

```json
{"exit_code":0,"grant_id":"","stderr":"","stdout":"[REDACTED:API_KEY]\n"}
```

The command really ran with `API_KEY` set to your value; the daemon replaced that value in the output before it left the process. With "Allow for 1h", `grant_id` carries the grant's ID. If you deny, the agent gets a tool error `denied: user_denied` and the command does not run. The same thing from the CLI:

```sh
cd ~/projects/demo
grantd run --secrets API_KEY -- printenv API_KEY
# [REDACTED:API_KEY]
echo $?
# 0
```

Exit codes are the command's own, with these additions: 77 you or the approver denied it, 78 a hard rule refused it (policy, presence tier, secret expired), 69 the daemon is not running, 124 timeout, 128+N interrupted by signal N. Details in the [CLI reference](#cli-reference).

**9. Check the record.**

```sh
grantd audit            # newest first: decision, caller, command, secrets, exit code
grantd audit verify     # audit chain ok (N entries)
grantd grants           # active grants; `grantd grants revoke --all` to drop them
```

One thing to know before you rely on this for real commands: the command runs with the **daemon's** environment (plus the injected secrets), not your shell's or the agent's. Under `grantd service install` that is the environment launchd gives the job plus the `PATH` that `service install` recorded: by default the (absolute entries of the) `PATH` of the shell you ran it from, or whatever you pass with `--path`. Re-run `grantd service install` after changing your `PATH` (see [Environment of the child process](#environment-of-the-child-process)).

### Troubleshooting

| Symptom | Cause |
|---|---|
| `grantd: grantd daemon is not running ... start it with grantd daemon` (exit 69) | Nothing is listening on the socket. `grantd service install`, or `grantd daemon`. |
| `vault not initialized; run grantd init` | The daemon is up but there is no vault yet. Run `grantd init`; the daemon picks it up without a restart. |
| `init` fails: Secure Enclave unavailable (`-34018`) | `make sign` does not fix this (MANUAL-TEST-MACOS.md §2a, outcome D); for a from-source build, a VM or a Mac without a Secure Enclave use `grantd init --keychain-fallback` (no flag is needed afterwards) and read the tier consequences below. |
| `denied (approver_unavailable)` (exit 77) | The prompt could not be shown: no GUI session (daemon started over SSH), no device password set, or `osascript` failed. It never degrades to an allow. |
| `refused (tier_unmet)` (exit 78) | A secret needs a presence tier your backends do not provide. Tiers are never downgraded. |
| `refused (policy_refused)` (exit 78) | `.grantd.yml` forbids the secret or command, or the file is unreadable, invalid, not owned by you, or world-writable. The message names the item. |
| `command not found` (exit 127) | `argv[0]` was not found on the daemon's `PATH` (see above). |

## How a run is decided

For each `run` request the daemon, in this order:

1. Validates it (protocol version, non-empty argv and secrets, absolute `cwd` that exists and is a directory, usable caller label). It resolves symlinks in `cwd` and uses the real path from here on.
2. Loads the nearest `.grantd.yml` and checks the requested secrets and argv against it. Failure: `refused/policy_refused`, exit 78.
3. Expands names and globs against the vault, derives environment variable names, and checks that no secret has expired and that both the key store and the approver meet the strictest `min_tier` among the secrets. Failure: `refused/tier_unmet` or `refused/secret_expired`.
4. Looks for an active grant that covers the request. If there is one, the run is allowed (`allowed_grant`).
5. Otherwise asks the human, one prompt at a time (prompts are serialised so an agent cannot stack dialogs). Deny: `denied/user_denied`, exit 77.
6. Decrypts the secrets (in the daemon's memory) and builds the environment. If that fails, it writes one `error` row and answers with the failure.
7. Writes the allow decision to the audit log with reason `released` **before the command is spawned**. If that write fails, the plaintext is discarded and nothing is started.
8. Starts the command, streams redacted output, and writes a second audit row (`completed`) with the exit code and duration.

## CLI reference

### `grantd`

Global flags: `-h/--help`, `-v/--version`. `grantd completion` (bash, zsh, fish, powershell) is the stock cobra completion generator.

```
grantd lets agents run commands that need secrets without ever receiving a plaintext secret, and without any release happening unapproved by a human.

Usage:
  grantd [command]

Available Commands:
  audit       Inspect and verify the audit log
  completion  Generate the autocompletion script for the specified shell
  daemon      Run the grantd daemon in the foreground
  delete      Delete a secret
  grants      List or revoke grants
  help        Help about any command
  import      Import secrets from a .env file
  init        Create the vault and wrap its data key in the KeyStore
  list        List secret names and metadata (never values)
  masked      Show a secret's masked form (last 4 characters only)
  mcp         Run the stdio MCP server (thin shim over the daemon socket)
  run         Run a command with secrets injected as env vars (output redacted)
  service     Manage the background service (launchd / systemd --user / Windows task)
  set         Store a secret (value from stdin or hidden prompt)
  show        Print a secret to the terminal (presence-gated, TTY only)
  status      Show daemon, vault and backend status

Flags:
  -h, --help      help for grantd
  -v, --version   version for grantd

Use "grantd [command] --help" for more information about a command.
```

### `grantd init`

Creates the vault and its key; does not need the daemon. Refuses if a vault already exists at the path. `--keychain-fallback` exists only here: if the Secure Enclave is unavailable it creates a Keychain-protected key (dialog tier, weaker) instead of failing; later commands need no flag. See [Presence tiers](#presence-tiers-and-the-keychain-fallback).

```
Create the vault and wrap its data key in the KeyStore

Usage:
  grantd init [flags]

Flags:
  -h, --help                help for init
      --keychain-fallback   macOS: if the Secure Enclave is unavailable, protect the vault key with a Keychain item (dialog tier, weaker) instead of failing; recorded in the vault, so later commands need no flag
```

### `grantd set`

Goes through the daemon (so the daemon must be running). Fails with `secret_exists` unless `--overwrite`. `--expires 30d` accepts Go durations plus `Nd` and `Nw`. The value is limited to 1 MiB and must not be empty. **Not presence-gated.**

```
Store a secret. The value is read from stdin when it is not a terminal (`printf %s "$V" | grantd set NAME`; one trailing newline is stripped), otherwise from a hidden prompt. It is never accepted as an argument.

Usage:
  grantd set NAME [flags]

Flags:
      --expires string    expiry, e.g. 30d
  -h, --help              help for set
      --min-tier string   minimum presence tier: none, dialog, hardware (none means the vault default)
      --notes string      free-form notes
      --overwrite         replace the secret if it already exists
      --socket string     socket path (default: $GRANTD_SOCKET or the platform default)
      --tags strings      comma-separated tags
      --url string        URL associated with the secret
```

### `grantd list`

Prints name, tier, expiry date, tags and URL. `--expiring 7d` includes already-expired secrets.

```
List secret names and metadata (never values)

Usage:
  grantd list [flags]

Flags:
      --expiring string   only secrets expiring within this duration, e.g. 7d
  -h, --help              help for list
      --socket string     socket path (default: $GRANTD_SOCKET or the platform default)
      --tag string        only secrets with this tag
```

### `grantd masked`

Prints `****` plus the last four characters for values of 12 or more characters, otherwise `********`. No approval required.

```
Show a secret's masked form (last 4 characters only)

Usage:
  grantd masked NAME [flags]

Flags:
  -h, --help            help for masked
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd delete`

**Not presence-gated.**

```
Delete a secret

Usage:
  grantd delete NAME [flags]

Flags:
  -h, --help            help for delete
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd show`

The only path that returns a value. Requires approval every time (it never uses or creates grants), and the CLI refuses with exit 78 unless stdout is a terminal. The terminal check is client-side; see the threat model.

```
Print a secret's value. Requires human presence approval every time and refuses unless stdout is a terminal, so the value cannot be piped into an agent's context or a file.

Usage:
  grantd show NAME [flags]

Flags:
  -h, --help            help for show
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd run`

Everything after `--` is the command, executed directly (no shell). `--secrets` takes names or globs (`aws/*`, `aws/**`), comma-separated or repeated. `--timeout` bounds the command only, not the time you take to answer the prompt; without it the daemon's cap of 1 hour applies, and larger values are capped at 1 hour. `--env-prefix` is prepended verbatim and must keep each name a valid uppercase environment variable name. Variables are named after the last path segment of the secret, uppercased with `.` and `-` turned into `_`; if two secrets would collide, all colliding secrets use their full name instead (`aws/api_key` becomes `AWS_API_KEY`). The command's stdin is `/dev/null`.

```
Run a command with secrets injected as environment variables. Output is
streamed back with every injected value replaced by [REDACTED:NAME].

Exit status: the command's own exit status; 124 on timeout; 77 when the
request was denied; 78 when it was refused (policy, presence tier); 69 when the
daemon is not running; 128+N when interrupted by signal N. Interrupting
grantd (SIGINT/SIGTERM) closes the connection, which makes the daemon stop the
command.

Usage:
  grantd run --secrets A,b/* [flags] -- cmd args...

Flags:
      --caller string       caller label recorded in grants and audit (informational)
      --env-prefix string   prefix for injected env var names
  -h, --help                help for run
      --secrets strings     secret names or globs to inject (comma-separated)
      --socket string       socket path (default: $GRANTD_SOCKET or the platform default)
      --timeout duration    kill the command after this duration, e.g. 10m
```

### `grantd grants`

Bare `grants` is `grants list`. The `STANDING` column says `standing` for grants created with `grants add` (the others, made by the dialog's "Allow for N", show `-`); `EXPIRES` is the time left. Rows that fail authentication are shown as `TAMPERED` and never match; revoke them. Neither list nor revoke needs approval; `add` always does.

```
List or revoke grants

Usage:
  grantd grants [flags]
  grantd grants [command]

Available Commands:
  add         Create a standing grant (long-lived, you approve it once)
  list        List active grants
  revoke      Revoke one grant by ID, or all with --all

Flags:
  -h, --help            help for grants
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)

Use "grantd grants [command] --help" for more information about a command.
```

### `grantd grants add`

Creates a [standing grant](#standing-grants). Example: `grantd grants add --caller claude-code --secrets DB_URL --ttl 30d -- php artisan`.

```
Create a standing grant: for the next --ttl, requests from --caller to run a
command starting with the given prefix, in --cwd or below it, asking only for
the listed secrets, are released without a prompt.

  grantd grants add --caller claude-code --secrets DB_URL,aws/* --ttl 30d -- php artisan

Everything after -- (or after --cmd, which must then be the last flag) is the
command prefix, so "php artisan" covers "php artisan migrate" but not "php x".
--caller has no default: say who the grant is for. --cwd defaults to the
current directory. --uses N ends the grant after N releases.

You approve it once, in a dialog that says "standing grant" and states the
duration, followed by Touch ID. The repo policy's max_grant_ttl limits only
the "Allow for N" button of a normal prompt, not this. A standing grant lasts
at most 90 days, or less if the policy sets max_standing_grant_ttl; a longer
--ttl is refused, not shortened. Revoke it with "grantd grants revoke ID".

Any program that can reach the daemon socket can send this request, so only
approve a standing-grant dialog that you started yourself.

Exit status: 77 when you cancelled or the dialog could not be shown, 78 when
the repo policy or the secret's presence tier refused it.

Usage:
  grantd grants add --caller NAME --secrets A,b/* --ttl 30d [--cwd DIR] [--uses N] -- cmd args... [flags]

Flags:
      --caller string     who the grant is for, e.g. claude-code (required, no default)
      --cmd               the rest of the line is the command prefix (same as --)
      --cwd string        directory the grant covers, with its subfolders (default: current directory)
  -h, --help              help for add
      --secrets strings   secret names or globs the grant covers (comma-separated)
      --socket string     socket path (default: $GRANTD_SOCKET or the platform default)
      --ttl string        how long the grant lasts, e.g. 30d, 12h (required; at most 90d)
      --uses int          end the grant after N releases (default: unlimited within --ttl)
```

### `grantd grants list`

```
List active grants

Usage:
  grantd grants list [flags]

Flags:
  -h, --help            help for list
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd grants revoke`

```
Revoke one grant by ID, or all with --all

Usage:
  grantd grants revoke [ID] [flags]

Flags:
      --all             revoke every grant
  -h, --help            help for revoke
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd audit`

Bare `audit` is `audit list`; `--limit` applies to the list (default 100, at most 1000). A run appears as a `completed` row above its `released` row.

```
Inspect and verify the audit log

Usage:
  grantd audit [flags]
  grantd audit [command]

Available Commands:
  export      Export the audit log (CSV)
  list        List recent audit entries (newest first; a run is a completed row above its released row)
  verify      Verify the HMAC chain

Flags:
  -h, --help            help for audit
      --limit int       maximum entries to show (default 100)
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)

Use "grantd audit [command] --help" for more information about a command.
```

### `grantd audit list`

```
List recent audit entries (newest first; a run is a completed row above its released row)

Usage:
  grantd audit list [flags]

Flags:
  -h, --help            help for list
      --limit int       maximum entries to show (default 100)
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd audit verify`

```
Verify the HMAC chain

Usage:
  grantd audit verify [flags]

Flags:
  -h, --help            help for verify
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd audit export`

```
Export the audit log (CSV)

Usage:
  grantd audit export [flags]

Flags:
      --csv             export as CSV (the only format) (default true)
  -h, --help            help for export
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd import`

Reads `KEY=value` lines (`export` prefix, quotes, `#` comments; no `${VAR}` expansion; keys must match `[A-Za-z_][A-Za-z0-9_]*`). `FILE` may be `-`. Empty values are skipped. Duplicate keys: the last wins. **Not atomic**: the CLI sends one `set` per key, so a daemon error midway leaves a partial import.

```
Import KEY=value pairs from a .env file (FILE may be - for stdin). Each key becomes a secret with default metadata. The file is parsed here; values go to the daemon one `set` at a time. Names are validated and conflicts detected before anything is written, but a daemon error midway can leave a partial import.

Usage:
  grantd import FILE [flags]

Flags:
      --dry-run              show what would be imported without writing
  -h, --help                 help for import
      --on-conflict string   when a name already exists: skip, overwrite or error (default "error")
      --socket string        socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd daemon`

Runs in the foreground until SIGINT/SIGTERM. Opens the vault at start if it exists (so a bad vault fails at start, not at the first request); if it does not exist yet it is opened as soon as `grantd init` creates it. Creates the socket (0600), refuses to start if another daemon answers on it, and replaces a stale socket.

```
Run the grantd daemon in the foreground

Usage:
  grantd daemon [flags]

Flags:
  -h, --help            help for daemon
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd service`

macOS only in v0.1.

```
Manage the background service (launchd / systemd --user / Windows task)

Usage:
  grantd service [command]

Available Commands:
  install     Install and start the service
  status      Show service status (exit 3 if not installed)
  uninstall   Stop and remove the service

Flags:
  -h, --help   help for service

Use "grantd service [command] --help" for more information about a command.
```

### `grantd service install`

Writes `~/Library/LaunchAgents/dev.grantd.daemon.plist` and bootstraps it into your GUI session. Idempotent: run it again after moving or rebuilding the binary, or after changing your `PATH`. The job runs `<exe> daemon`. It records `PATH` in the plist (only absolute entries, in order, without duplicates; by default the `PATH` of the shell running `install`, or the value of `--path`) and `GRANTD_SOCKET` if you pass `--socket`; those are the only variables the plist defines, and commands started by `grantd run` inherit them from the daemon.

```
Install and start the service

Usage:
  grantd service install [flags]

Flags:
      --exe string       grantd binary or .app bundle the service runs (default: this executable)
  -h, --help             help for install
      --log-dir string   directory for daemon logs (default: ~/Library/Logs/grantd)
      --path string      PATH the daemon (and the commands it runs) get (default: PATH of this shell)
      --socket string    socket path to export to the daemon as GRANTD_SOCKET
```

### `grantd service uninstall`

```
Stop and remove the service

Usage:
  grantd service uninstall [flags]

Flags:
  -h, --help   help for uninstall
```

### `grantd service status`

```
Show service status (exit 3 if not installed)

Usage:
  grantd service status [flags]

Flags:
  -h, --help   help for status
```

### `grantd mcp`

See [MCP server](#mcp-server).

```
Run a Model Context Protocol server on stdin/stdout exposing secret_list, secret_exists,
secret_masked and secret_run. No tool returns a secret value. Logs go to stderr only.
If the daemon is not running the shim tries to start it once.

Usage:
  grantd mcp [flags]

Flags:
  -h, --help            help for mcp
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### `grantd status`

Works without a vault. Shows the daemon's PID, version, socket, uptime, whether a vault exists, the key store and approver tiers, the number of secrets and active grants. Prints a `WARNING:` line if any grant rows failed authentication. Exits 69 if the daemon is not running.

```
Show daemon, vault and backend status

Usage:
  grantd status [flags]

Flags:
  -h, --help            help for status
      --socket string   socket path (default: $GRANTD_SOCKET or the platform default)
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `run`: the command exited 0. |
| 1 | Any other failure: bad request, secret not found, internal error, `audit verify` found a broken chain, usage errors. |
| 69 | The daemon is not running (`EX_UNAVAILABLE`). |
| 77 | Denied: you pressed Deny, the approval could not be obtained, or no grant matched and the approver refused (`EX_NOPERM`). |
| 78 | Refused by a hard rule: policy, presence tier, expired secret, `show` not on a terminal (`EX_CONFIG`). |
| 124 | Timeout. For `run`: the command exceeded `--timeout` and its process group was killed; or the request's overall deadline (command budget plus ten minutes to answer the prompt) expired. |
| 128+N | `grantd run` was interrupted by signal N (130 for Ctrl-C, 143 for SIGTERM). |
| 126, 127 | From `run`: the command could not be executed / was not found. |
| other | `grantd run` exits with the command's own exit status. A command that itself exits 69, 77 or 78 is indistinguishable from the codes above; check stderr if it matters. |

`grantd service status` exits 3 when the service is not installed.

## MCP server

`grantd mcp` runs a stdio [Model Context Protocol](https://modelcontextprotocol.io) server. It is a thin shim: each tool call becomes one daemon request, and policy, grants, prompts, redaction and audit stay in the daemon.

| Tool | Arguments | Returns |
|---|---|---|
| `secret_list` | none | `{secrets: [{name, tags, url, expires_at, min_tier}]}`. No values, no notes. |
| `secret_exists` | `name` | `{exists}` |
| `secret_masked` | `name` | `{masked}`: `****WXYZ` (last four characters) for values of 12 or more characters, `********` otherwise. |
| `secret_run` | `argv[]`, `secrets[]` (both required), `cwd?` (absolute), `timeout_s?` | `{exit_code, stdout, stderr, grant_id}` |

There is deliberately no tool that returns a value, and no `show`, `set`, `delete` or `grants` over MCP. `TestSourceNeverReferencesShow` fails if the `internal/mcp` package ever mentions the `show` op. (This is a property of the shim, not of the daemon: anything that can reach the socket can send a `show` request, which still needs your approval. See the threat model.)

- **Errors.** A daemon refusal (`denied`, `refused`, `not_found`, ...) comes back as an MCP tool error (`isError: true`) with text such as `denied: user_denied`, never as a protocol error.
- **Output.** `stdout` and `stderr` are already redacted by the daemon and are each capped at 1 MiB with a truncation marker.
- **Caller.** The `caller` sent to the daemon is the MCP client's name from the `initialize` handshake, lowercased, with anything outside `[a-z0-9_.-]` replaced by `_`, at most 64 characters, `mcp` if empty. It is self-reported and not authenticated.
- **Working directory.** `cwd` defaults to the shim's own working directory (Claude Code normally starts MCP servers in the project directory; if yours does not, the agent must pass `cwd`). A relative `cwd` is rejected.
- **Blocking.** A `secret_run` call blocks while a prompt is on screen. The daemon allows up to ten minutes (the approval grace) on top of the command timeout.
- **Daemon auto-start.** If nothing is listening, the shim spawns `grantd daemon --socket <path>` once (detached, own session, stdio on `/dev/null`) and waits up to 5 seconds for the socket, then retries; after a failed attempt it does not try again for 30 seconds. The spawned daemon gets a minimal environment: `HOME`, `USER`, `LOGNAME`, `PATH`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `DBUS_SESSION_BUS_ADDRESS`. In particular `GRANTD_HOME` is **not** forwarded and the daemon's output goes nowhere. If you use a non-default `GRANTD_HOME`, run the daemon yourself. Prefer `grantd service install`.
- **Logging.** Logs go to stderr only (stdout is the protocol channel) and contain op names, never tool arguments.
- **Custom socket.** `grantd mcp --socket PATH`, or `GRANTD_SOCKET` set in the shell that starts `claude`, not in the MCP config.

To try it without Claude Code, point an MCP client at it, e.g. `npx @modelcontextprotocol/inspector grantd mcp`.

## Environment, paths and files

| Name | Meaning |
|---|---|
| `GRANTD_HOME` | If set, the vault is `$GRANTD_HOME/vault.db`. It does **not** move the socket. Used by tests and for relocation. |
| `GRANTD_SOCKET` | If set, the socket path used by the daemon and every client. `--socket` overrides it per command. |
| `XDG_DATA_HOME` | If set and absolute: vault at `$XDG_DATA_HOME/grantd/vault.db` (on every platform, including macOS, unless `GRANTD_HOME` is set). On non-macOS also the socket directory. |
| `XDG_RUNTIME_DIR` | If set: socket at `$XDG_RUNTIME_DIR/grantd.sock`. |
| `GRANTD_DEV_APPROVE` | Test builds only (`-tags grantd_dev`): `allow` makes the dev approver auto-allow; `allow-no-standing` does the same but denies standing-grant requests (`grants add`); anything else auto-denies. Does nothing in a production build. |
| `GRANTD_MANUAL_TEST` | Enables the hardware-touching tests in [MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md). |

Resolution order for the **vault**: `$GRANTD_HOME/vault.db`, then `$XDG_DATA_HOME/grantd/vault.db`, then `~/Library/Application Support/grantd/vault.db` (macOS) or `~/.local/share/grantd/vault.db`.

Resolution order for the **socket**: `$GRANTD_SOCKET`, then `$XDG_RUNTIME_DIR/grantd.sock`, then `~/Library/Application Support/grantd/grantd.sock` (macOS) or `$XDG_DATA_HOME/grantd/grantd.sock` (default `~/.local/share/grantd/grantd.sock`). The path must be at most 103 bytes on macOS (107 on Linux).

| Path | What |
|---|---|
| `~/Library/Application Support/grantd/vault.db` (+ `-wal`, `-shm`) | The vault: secrets, grants, audit log. Directory 0700 if grantd created it, file 0600. The daemon refuses to open a vault file that is group- or world-accessible. |
| `~/Library/Application Support/grantd/grantd.sock` | The daemon socket, mode 0600, same-UID peers only. Removed on clean shutdown; a stale one is replaced at start. |
| `~/Library/LaunchAgents/dev.grantd.daemon.plist` | The service definition (label `dev.grantd.daemon`). |
| `~/Library/Logs/grantd/daemon.out.log`, `daemon.err.log` | Service logs (`--log-dir` changes it). The daemon logs op, caller, cwd, argv and outcome for every request: command lines are in there, secret values are not. |
| Keychain: key tag `dev.grantd.vault-kek` | The Secure Enclave P-256 key that wraps the vault key. It lives in the data-protection keychain and is invisible to `security` and Keychain Access. |
| Keychain: generic password, service `dev.grantd`, account `vault-kek` | Only with the Keychain fallback: the 32-byte key-encryption key. `security find-generic-password -s dev.grantd -a vault-kek` finds it (add `-g` to print it; don't). |
| `<project>/.grantd.yml` | Per-repo policy. |

### Environment of the child process

A command started by `run` gets a copy of the **daemon's** environment with the injected variables added (an injected variable replaces one of the same name). It does not get the environment of the `grantd run` process or of the agent. This is deliberate in one respect: an agent cannot smuggle `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `BASH_ENV` or a different `PATH` into an approved run. It is a trap in another: a daemon started by `grantd service install` has launchd's environment plus the `PATH` recorded at install time (the plist defines nothing else beyond an optional `GRANTD_SOCKET`), so a tool installed after that, or in a directory that was not on your `PATH` when you ran `install`, is not found until you re-run it. A daemon you start from your shell has your shell's environment; one the MCP shim starts has only the shim's `HOME`, `USER`, `LOGNAME`, `PATH`, `TMPDIR`, `LANG` and `XDG_*` variables. `argv[0]` without a `/` is looked up on the child's `PATH` (absolute entries only); a name with a `/` is taken relative to `cwd`. The child's stdin is `/dev/null`, it runs in its own process group, and when its leader exits the rest of the group is killed.

### Presence tiers and the Keychain fallback

Every secret has a `min_tier`: `none`, `dialog` or `hardware`. A run is refused (`tier_unmet`, exit 78) if either the key store or the approver provides less than the strictest `min_tier` among the requested secrets. Tiers are never downgraded. On macOS:

| Backend | Tier |
|---|---|
| Secure Enclave key store | `hardware` (the key is hardware-bound and not exportable) |
| Keychain fallback key store (`--keychain-fallback`) | `dialog` |
| LocalAuthentication approver (Touch ID, password fallback) | `hardware` |

`grantd init` makes `min_tier` default to the key store's tier, so with the Secure Enclave new secrets are `hardware`, and with the fallback they are `dialog`. A vault created with a stronger key store refuses to open with a weaker one. `--keychain-fallback` exists only on `grantd init`. It only decides what `init` may create; the wrapped key records which mechanism protects it, so the daemon, the service and the MCP auto-start open the vault with no flag. After the key store unwraps the vault key the daemon checks its tier again and refuses to run a vault on a weaker key store than the one it was created with. The weaker mode puts the key-encryption key in an ordinary Keychain item, readable by processes that run as you (macOS may show its own "wants to use your confidential information" prompt to a binary other than the one that created the item; I did not test whether that is a real barrier); protection is then your login session plus the approval prompt. Read [THREAT-MODEL.md](THREAT-MODEL.md) before using it for anything you care about.

## Policy files

A policy is a `.grantd.yml` committed with the repository:

```yaml
version: 1
secrets:            # names or globs this repo may request
  - aws/*
  - DB_URL
commands:           # allowed argv prefixes
  - [php, artisan]
  - [aws]
  - [./deploy.sh]
max_grant_ttl: 4h   # optional; Go durations or Nd; default 1h
max_standing_grant_ttl: 30d   # optional; caps `grants add`; no default
```

Semantics, all of which are enforced in `internal/policy` and `internal/broker`:

- **A policy restricts; it never grants.** Without a policy, every request needs approval and the prompt says "(no policy)". With one, requests outside it are refused (exit 78, `policy_refused`, message naming the secret or the command) before any prompt, and requests inside it still need approval or a matching grant.
- **Lookup is by nearest ancestor.** Starting at the request's `cwd` (symlinks resolved) and walking up to `/`, the first `.grantd.yml` found is the policy. Policies are not merged: a policy in a subdirectory replaces one higher up, in either direction, looser or stricter. Treat changes to `.grantd.yml` as security-relevant code review.
- **Broken means refused.** A policy file that exists but is unreadable, is not a regular file, is not owned by the current user, is world-writable, is over 1 MiB, has an unknown key, is not exactly one YAML document, or has `version` other than 1 refuses the request. The search never skips past a broken file to a looser one. (Group-writable is allowed. The ownership and mode checks are Unix-only.)
- **Secrets.** A requested literal name must equal a policy entry or match a policy glob (doublestar syntax, so `aws/*` matches one level and `aws/**` any depth). A requested **glob** (`--secrets 'aws/*'`) is allowed only if that exact text appears in the policy, even if the policy has `**`. An empty or missing `secrets` list allows nothing.
- **Commands.** `argv` must start, element for element, with one of the listed prefixes. Matching is textual on what the caller typed: `[./deploy.sh]` matches `./deploy.sh` and not `/abs/path/deploy.sh`. An empty or missing `commands` list allows nothing. A prefix like `[sh, -c]` or `[bash]` allows arbitrary shell code; list the narrowest prefix you can.
- **`max_grant_ttl`** is the N the dialog offers on "Allow for N", and the cap on the grant that button creates, but never more than 24 hours (`max_grant_ttl: 7d` offers 24h). Absent, it is 1 hour. Without a policy file the dialog offers 1 hour. It does **not** limit standing grants: the cap is for prompts an agent can trigger, and a standing grant is something you create on purpose with `grants add`.
- **`max_standing_grant_ttl`** (optional) caps standing grants for this repo, with the same syntax as `max_grant_ttl`. Absent means no repo cap. It can only lower the daemon's 90-day ceiling, never raise it. A `grants add --ttl` above the ceiling is refused with `bad_request`, not shortened.
- **Grant scope follows the policy.** When you press "Allow for N", the grant's command prefix is the longest policy prefix that the request's argv starts with (the whole argv if there is no policy). With `commands: [[php, artisan]]`, approving `php artisan sync` for an hour permits every `php artisan ...` command in that directory for that hour. The dialog's "Allow for N covers:" line shows that prefix, so you can see the scope before you accept it; keep policy prefixes narrow.

## Grants

A grant is what lets a release happen without a prompt. There are two kinds: the **dialog grant** that "Allow for N" creates (at most 24 hours), and the **standing grant** that you create with `grantd grants add` (at most 90 days; see [Standing grants](#standing-grants)). They match requests in exactly the same way.

A request matches a grant when **all** of these hold:

- the `caller` string is identical (it is a label the client supplies; it is not authenticated);
- the request's `cwd`, after symlink resolution, equals the grant's directory or is inside it (lexical prefix on path components: `/a/foo` is not under `/a/f`);
- every requested secret is covered: a literal name by an equal entry or by a glob entry that matches it; a requested glob only by a grant entry with the identical text;
- `argv` starts with the grant's command prefix, element for element;
- the grant has not expired (it expires at exactly its `expires_at`) and, if it has a use count, has uses left;
- the stored row authenticates (below).

The grant's command scope is the longest policy command prefix that the request's argv starts with, else the full argv; its directory is the request's resolved working directory. The grant records the secrets **as requested** (`aws/*`), not as expanded at approval time, so a glob grant also covers a matching secret you add later. The TTL of a dialog grant is the dialog's N: the policy's `max_grant_ttl` capped at 24 hours, or 1 hour with no policy (it is not user-selectable and there is no flag to change the default). Allow-once never creates a grant. A grant with a use limit (`uses_remaining`) can only be created with `grants add --uses N`. `grantd grants` lists active grants; `grantd grants revoke ID` and `grantd grants revoke --all` delete them (neither needs approval).

**Grants are authenticated.** Each row carries an HMAC-SHA256 under `vault.DeriveKey("grant-mac")` (a key derived from the vault key, which only the daemon holds) over the row's id, caller, directory, secrets, command prefix, created/expiry times, remaining uses and kind (so a dialog grant cannot be relabelled as a standing one or the reverse). A row that someone inserted or edited in `vault.db` fails verification: it never matches, `grantd grants` lists it as `TAMPERED: failed authentication, ignored (revoke it)`, `grantd status` prints a `WARNING:` line with the count, and the daemon logs it once at WARN. Finite use counts are decremented with a compare-and-swap that rewrites the MAC. What the MAC does not stop: deleting rows (that only revokes), and **replaying an older genuine row** that was saved earlier, within its lifetime (reviving a revoked grant, or resetting `uses_remaining`). Grants created before this existed are dropped on upgrade (you get asked again). For a standing grant the replay window is its whole lifetime rather than an hour.

What a grant binds to is **the argv text and the directory, not the program's contents.** If you grant `php artisan` in `~/projects/demo`, an agent that can edit files in that tree can change what `artisan` does and use the grant. Approving "Allow for N" is approving the repository's code to run with those secrets for that long.

### Standing grants

```sh
grantd grants add --caller claude-code --secrets DB_URL,aws/* --ttl 30d -- php artisan
grantd grants add --caller claude-code --secrets API_KEY --ttl 12h --cwd ~/projects/demo --uses 20 -- ./deploy.sh
```

A standing grant is a grant that **you** create, up front, for a long time, instead of answering a prompt later. `--caller` is required (no default): you state who it is for. `--secrets` takes names and globs; everything after `--` (or after `--cmd`) is the command prefix, so `php artisan` also covers `php artisan migrate`; `--cwd` defaults to the current directory and covers its subfolders; `--uses N` ends the grant after N releases. The daemon validates it like a run (the directory must exist, the secrets must exist and not be expired, and a `.grantd.yml` that does not allow those secrets and that command refuses it with `policy_refused`).

The ceilings: `--ttl` may be at most **90 days**, and at most the policy's `max_standing_grant_ttl` if the nearest `.grantd.yml` sets one. Above the ceiling the request is refused with `bad_request` and a message naming the limit; it is never shortened. The policy's `max_grant_ttl` is not involved.

You approve it once. The dialog is not the release prompt:

```
Create a standing grant?

claude-code may run `php artisan …` with DB_URL, aws/* (aws/access_key) in /Users/you/projects/demo and subfolders for the next 30 days, without further prompts.

Only continue if you just ran `grantd grants add` yourself.

[ Cancel ]   [ Create standing grant ]
```

Cancel is the default (Esc and 120 seconds of silence cancel too). A use limit shows as "(at most 5 runs)". Touch ID follows, and its text repeats it ("Create standing grant for 30 days: ..."). Nothing is stored until both succeed. The dialog cannot show the duration in large print (`display dialog` has no font control); it is in the first sentence. After that, matching runs are released with no prompt, audited as `allowed_grant`; the creation itself is one `allowed_new_grant` row with reason `standing`. `grantd grants` marks the grant in its `STANDING` column; `grantd grants revoke ID` removes it.

**Anything that can reach the socket can ask for this dialog.** The daemon cannot tell `grantd grants add` from an agent writing the same JSON line to the socket, and the `caller` in the dialog is whatever the sender claimed. So the protection is the human reading the dialog: if you did not just run `grants add`, press Cancel. A standing grant you approve is, for its whole lifetime, an unattended release of those secrets to any process that claims the caller name and runs that command prefix in that directory (see the grant caveats above, and the [threat model](THREAT-MODEL.md)). Keep it narrow: a specific command prefix, a specific directory, the shortest `--ttl` that works, and `--uses` where a count makes sense.

## Redaction

The daemon replaces every exact, byte-for-byte occurrence of each injected value in the command's stdout and stderr with `[REDACTED:NAME]`, where NAME is the secret's vault name (`aws/access_key`), not the environment variable name.

What is guaranteed (and tested in `internal/runner` and `internal/e2e`):

- Matching works across read boundaries: a value split between two chunks is still caught, and only the shortest possible suffix is held back, so unrelated output streams without delay.
- When one value is a prefix of another, the longer match wins at that position. If two secrets share a value, the lexicographically smallest name is used.
- The same scrubbing is applied to the daemon's own error messages and to the `argv` written to the audit log.
- Short values (under 4 bytes) are still redacted, and will also mangle unrelated text that happens to match; don't store them.
- Redacted frames cannot be split mid-character: an incomplete UTF-8 sequence is held until it is complete. Output that is not valid UTF-8 is not preserved (it passes through JSON encoding on the way to the client).

What is **not** caught:

- Encoded or transformed values: base64, hex, URL-encoding, JSON escaping of quotes or newlines, reversed or hashed text, a command that prints the value one character per line, or anything that splits the value. (`echo $KEY | base64` returns the key to the agent.)
- Substrings, prefixes and suffixes of a value.
- Output that doesn't go to stdout or stderr: files, network, other processes, or the child's environment as seen by `ps` (a process running as you can read the environment of your own processes; `ps -Eww` does this on macOS, which I verified for a non-system binary).

Redaction is defence in depth against accidents. It is not what keeps a malicious command from leaking a secret; the approval is.

## Audit

Every decision is appended to an audit table in the vault database: time, caller, `cwd`, `argv`, secret names requested (never values), decision, grant ID, exit code, duration, reason. Each `run` that is released writes **two rows**:

1. the allow decision (`allowed_once`, `allowed_new_grant` or `allowed_grant`) with reason `released`, written after the secrets are decrypted in the daemon and **before the command is spawned**. If this row cannot be written, nothing is started. Both rows have any injected value scrubbed from `argv`, so a caller that puts a value on the command line does not leave it in the audit table.
2. a `completed` row with the exit code, duration and the same grant ID, written when the command ends. Its reason is empty for a normal exit, or `timeout`, `canceled`, `command not found`, `cannot execute command`, or `not started: ...` (the process could not be started; no exit code).

A `released` row with no `completed` row after it means the daemon died mid-run. Refusals, denials and failures before the release (an unknown secret, an expired secret, a failed decryption) are one row each (`denied_user`, `refused_policy`, `refused_tier`, `error`). `set`, `delete` and `show` are recorded too, as `allowed_once` with the verb as the reason.

**Integrity.** Rows are chained: `HMAC_n = HMAC-SHA256(key, canonical(row_n) || HMAC_{n-1})`, with a key derived from the vault key (HKDF, label `audit-hmac`) that the daemon holds. `grantd audit verify` recomputes the whole chain and reports the first bad row. The table has triggers that abort `UPDATE` and `DELETE`.

**What this does not give you.**

- The triggers stop the application, not someone with write access to the file, who can drop them. Without the key such a person cannot forge a valid chain, so edits, reordering and deletions from the middle are detected by `verify`.
- **Truncation is not detected.** Deleting the newest rows leaves a valid chain; there is no external anchor (a signed head, a remote log). An attacker who can write the file can erase their most recent activity.
- The audit log and the grants table are independent: a replayed genuine grant row (see Grants) is not visible in the audit log except as repeated `allowed_grant` rows for a grant you had revoked.

`grantd audit export` prints the log as CSV (`id, ts, caller, cwd, argv, secrets, decision, grant_id, reason, exit_code, duration_ms`); `argv` and `secrets` are JSON arrays. Exports larger than 1 MiB are refused over the socket; use `audit list --limit`.

## Manual testing on a Mac

The Secure Enclave key store and the Touch ID approver need real hardware and a desktop session, so CI cannot run them. [MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md) is the checklist, including the signing decision tree and what to record.

## Development

```sh
make build        # production binary, bin/grantd
make ci           # everything CI runs: build vet lint test dev-test cover tools-check
make test         # go test -race ./...
make dev-test     # go test -race -tags grantd_dev ./...  (includes the TierNone dev backends)
make vet lint     # go vet and staticcheck, with and without the dev tag
make cover        # coverage summary
```

Layout: `cmd/grantd` (cobra commands), `internal/daemon` (socket server, peer-credential check), `internal/broker` (op handlers; the one place policy, grants, approver, vault, runner and audit meet), `internal/vault` (SQLite, AES-256-GCM), `internal/policy`, `internal/grant`, `internal/runner` (spawn, env injection, redaction), `internal/audit`, `internal/proto` (wire types, see [PROTOCOL.md](PROTOCOL.md)), `internal/mcp`, `internal/keystore` and `internal/approve` (interfaces, with `darwin` and `dev` implementations), `internal/service` (launchd).

**The `grantd_dev` build tag.** The tests need a key store and approver that work headless, so there are `TierNone` backends in `internal/keystore/dev` and `internal/approve/dev`: a key store that wraps the vault key under a constant, public key, and an approver that auto-allows or auto-denies according to `GRANTD_DEV_APPROVE`. They are insecure by construction and are only compiled with `-tags grantd_dev`. In a normal build the `dev` packages contain only a `disabled.go` whose `Open` returns `ErrDisabled`, and `cmd/grantd/backends_dev.go` (the only file that selects them) carries the same tag, so a production binary has no code path to them. `make ci` runs `vet`, `lint` and tests both with and without the tag. To exercise the whole stack on any machine, headless:

```sh
go build -tags grantd_dev -o /tmp/grantd-dev ./cmd/grantd
export GRANTD_HOME=$(mktemp -d) GRANTD_SOCKET=/tmp/grantd-dev.sock GRANTD_DEV_APPROVE=allow
/tmp/grantd-dev init && /tmp/grantd-dev daemon &
```

Never ship or run a `grantd_dev` binary against real secrets.

## License

Apache-2.0. See [LICENSE](../LICENSE).
