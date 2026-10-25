# Wire protocol

This is the protocol between a client (the `grantd` CLI, the MCP shim, or anything else) and the daemon, as implemented in `internal/proto` (`proto.go`, `codec.go`, `result.go`) and served by `internal/daemon` and `internal/broker`. The protocol version is **1**. The examples below are real exchanges captured from a build with the `grantd_dev` tag (so tiers are `none`); paths are shortened.

## Transport

- A Unix domain stream socket. Path: `$GRANTD_SOCKET`, else the platform default (see "Environment, paths and files" in [README.md](README.md)). On macOS: `~/Library/Application Support/grantd/grantd.sock`.
- The socket file is mode 0600; the daemon creates its directory as 0700 if it did not exist. On every accepted connection the daemon reads the peer's effective UID (`LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux) and rejects any peer whose UID differs from its own, or whose credentials cannot be read, with `refused` / `peer_rejected` before reading anything. The check identifies the **user**, not the program: every process running as that user is an authorised client.
- **One request per connection.** The client connects, sends one request line, reads zero or more stream frames and exactly one final response, and the server closes the connection. A second request needs a new connection (`client.Client` returns `ErrUsed` if you try).
- **Keep the write side open.** The daemon watches the connection for the client going away; any read result, including EOF from a half-close, cancels the request (for `run`, that stops the command: SIGTERM to its process group, SIGKILL two seconds later). Clients must send the request and then only read. This matters for tools like `nc`, which may close their sending side when stdin ends; write a small client instead.
- The daemon expects the request line within **5 seconds** of connecting, else it answers `bad_request`.

## Framing

- Each message is one JSON object on one line, terminated by `\n`. Writers emit compact JSON, so there are no raw newlines inside (newlines in strings are escaped). Readers skip empty lines.
- A line, including its newline, is at most **4 MiB** (`MaxLineBytes` = 4194304). A writer that would exceed it returns an error; a reader that meets a longer line fails, and the daemon answers `bad_request` / `bad_request` and closes the connection (a client that is still writing the oversized line may get a broken pipe before it can read the answer).
- Text is UTF-8. A stream frame's `data` is a JSON string, so output that is not valid UTF-8 is not preserved byte for byte (invalid sequences become U+FFFD). The daemon holds back an incomplete trailing multibyte sequence until it is complete, so characters are not split across frames.
- Server messages are told apart by their keys: a line containing `"stream"` is a stream frame; a line containing `"ok"` is the final response.

## Request

```json
{"v":1,"op":"run","caller":"claude-code","cwd":"/abs/path","argv":["php","artisan","sync"],"secrets":["API_KEY","aws/*"],"env_prefix":"","timeout_s":600}
```

Every field except `v` and `op` is optional on the wire (`omitempty`); which are meaningful depends on the op.

| Field | Type | Used by | Meaning |
|---|---|---|---|
| `v` | int | all | Protocol version; must be `1`. |
| `op` | string | all | `run`, `list`, `exists`, `masked`, `set`, `delete`, `show`, `grants`, `audit`, `status`. |
| `caller` | string | all | Informational, **untrusted** label (`claude-code`, `cli`, ...). Used in the dialog, in grant matching and in the audit log. At most 64 bytes with no control or non-printing characters; otherwise `run` and `show` are rejected (`bad_request`). Defaults to `cli`. |
| `cwd` | string | run, show | Absolute path. For `run` it must exist and be a directory; the daemon resolves symlinks and uses the real path. For `show` it is only displayed. |
| `argv` | string[] | run | The command and arguments, executed directly (no shell). Non-empty, `argv[0]` non-empty, at most 4096 elements. |
| `secrets` | string[] | run | Secret names or doublestar globs (`aws/*`, `aws/**`). Non-empty, no empty entries, at most 256. |
| `env_prefix` | string | run | Prepended verbatim to each injected variable name. |
| `timeout_s` | int | run, all | Command budget in seconds. `0` or absent: the daemon's cap, 1 hour. Larger values are capped at 1 hour. Negative: `bad_request`. It bounds the command only. The connection deadline is this budget **plus 10 minutes** for the human to answer the prompt. |
| `name` | string | exists, masked, set, delete, show | Secret name: `[A-Za-z0-9_/.-]+`, at most 256 bytes, no empty segments, no `..`, no leading or trailing `/`. |
| `value` | string | set | The secret. The only request field that carries a secret. Non-empty, at most 1 MiB. |
| `tags` | string[] | set | Tags (`[A-Za-z0-9_.:-]`, at most 64 characters each, at most 32). |
| `url`, `notes` | string | set | Free-form metadata, stored unencrypted. |
| `expires` | RFC 3339 time | set | Absolute expiry; must be in the future. (The CLI converts `30d`.) |
| `min_tier` | `"none"`, `"dialog"`, `"hardware"` | set | Minimum presence tier. Absent or `"none"`: the vault default. |
| `overwrite` | bool | set | Replace an existing secret. |
| `tag` | string | list | Only secrets with this tag. |
| `expiring_within_s` | int | list | Only secrets that expire within this many seconds (already-expired ones included). |
| `action` | string | grants, audit | grants: `list` (default), `revoke`, `revoke_all`. audit: `list` (default), `verify`, `export`. Anything else: `bad_request`. |
| `grant_id` | string | grants | The grant to revoke. |
| `limit` | int | audit list | Rows to return, newest first. Default 100, at most 1000. |

`proto.Request` implements `String()` and `GoString()` so that formatting a request never prints `value`.

## Stream frames

For `run`, zero or more frames arrive before the final response:

```json
{"stream":"stdout","data":"key=[REDACTED:API_KEY]\n"}
{"stream":"stderr","data":"oops\n"}
```

`stream` is `stdout` or `stderr`. `data` is already redacted. Order is preserved within a stream, not between the two (in the example below stderr arrives before stdout although the command wrote stdout first).

## Final response

```json
{"ok":true,"exit_code":0,"grant_id":"...","audit_id":"..."}
{"ok":false,"error":"denied","reason":"user_denied"}
```

| Field | Meaning |
|---|---|
| `ok` | Whether the op succeeded. |
| `exit_code` | `run` only, present (including `0`) when the command ran. Absent otherwise. |
| `grant_id` | `run`: the grant that authorised it or that the human's "Allow for N" created; absent for allow-once. `grants revoke`: the revoked ID. |
| `audit_id` | The audit row this request wrote, when it wrote one. For a `run` that was released it is the `completed` row. |
| `error` | On failure: the category. |
| `reason` | On failure: the specific cause. On a successful `run` that timed out: `timeout`. |
| `message` | Optional human-readable detail. Display only; programs should branch on `error` and `reason`. Already redacted; never carries a secret. |
| `result` | Op-specific payload (below), on success. |

### Categories (`error`) and CLI exit codes

| `error` | Meaning | `grantd` exit code |
|---|---|---|
| `denied` | A human, a missing approval, or an unavailable approver said no. | 77 |
| `refused` | A hard rule said no: policy, presence tier, expired secret, wrong peer. | 78 |
| `bad_request` | Malformed or unsupported request. | 1 |
| `not_found` | The named secret or grant does not exist. | 1 |
| `failed` | Accepted but did not complete: timeout, cancellation, internal error, vault not initialized. | 1, or 124 when the reason is `timeout` |

### Reasons (`reason`)

| `reason` | Category | When |
|---|---|---|
| `user_denied` | denied | The human pressed Deny (or Esc, or the dialog timed out, or authentication failed or was cancelled). |
| `approver_unavailable` | denied | The prompt could not be shown (no GUI session, no device password, `osascript` failed). Never an allow. |
| `no_grant` | denied | Defined in `proto` but not emitted by the current code. |
| `policy_refused` | refused | `.grantd.yml` forbids a secret or the command, or the policy file is unreadable, invalid, not owned by the user, or world-writable. `message` names the item. |
| `tier_unmet` | refused | The key store or approver provides less than a secret's `min_tier`. `message` says which. |
| `peer_rejected` | refused | The peer's UID is not the daemon's. |
| `secret_expired` | refused | A requested secret is past `expires_at`. |
| `not_tty` | refused | Defined for `show` run without a terminal; emitted by the CLI itself before it contacts the daemon, never by the daemon. |
| `bad_request` | bad_request | A malformed field; `message` often says which. |
| `unsupported_version` | bad_request | `v` is not 1. |
| `unknown_op` | bad_request | Unknown `op`. |
| `secret_exists` | bad_request | `set` without `overwrite` on an existing name. |
| `secret_not_found` | not_found | A named secret, or a literal or glob in `secrets` that matches nothing. |
| `grant_not_found` | not_found | `grants revoke` with an unknown ID. |
| `vault_not_initialized` | failed | No vault yet; `message`: run `grantd init`. |
| `timeout` | failed | The connection deadline expired (command budget plus approval grace), for example while waiting for the human. A command that merely overran its own `timeout_s` is a **successful** response with `exit_code` 124 and `reason: "timeout"`. |
| `canceled` | failed | The client went away or the daemon is shutting down. |
| `internal` | failed | Unexpected error. The cause goes to the daemon log, not to the client. |

## Ops

### `status`

Request: `{"v":1,"op":"status"}`. Works without a vault. Result:

```json
{"ok":true,"result":{"version":"dev","proto_v":1,"pid":8683,"started_at":"2026-10-25T14:15:46.228625+01:00","vault_initialized":true,"keystore_tier":"none","approver_tier":"none","secrets":2,"active_grants":0,"socket":"/tmp/gdd-8677.sock"}}
```

`keystore_tier` and `approver_tier` are `none`, `dialog` or `hardware`.

### `list`

Request: `{"v":1,"op":"list","tag":"prod"}`. Result is an array, sorted by name, never containing values:

```json
{"ok":true,"result":[{"name":"stripe/api_key","tags":["payments","prod"],"url":"https://dashboard.stripe.com","min_tier":"none","created_at":"2026-10-25T13:15:47.259Z","updated_at":"2026-10-25T13:15:47.259Z"}]}
```

Elements are `{name, tags?, url?, notes?, expires_at?, min_tier, created_at, updated_at}`. No approval is needed.

### `exists`, `masked`

```
>> {"v":1,"op":"exists","name":"stripe/api_key"}
<< {"ok":true,"result":{"exists":true}}
>> {"v":1,"op":"masked","name":"stripe/api_key"}
<< {"ok":true,"result":{"masked":"****2b7c"}}
```

`masked` is `****` plus the last four characters for a value of at least 12 characters, otherwise `********`. No approval is needed.

### `set`

Request fields: `name`, `value`, optionally `tags`, `url`, `notes`, `expires`, `min_tier`, `overwrite`. Not presence-gated. Success: `{"ok":true,"audit_id":"10"}`. Failures: `secret_exists` if the name exists and `overwrite` is not set, `bad_request` for an empty or oversized value, a bad name, an invalid tier or a past expiry.

```
>> {"v":1,"op":"set","name":"tmp/x","value":"<value>","tags":["t"]}
<< {"ok":true,"audit_id":"10"}
>> {"v":1,"op":"set","name":"tmp/x","value":"<value>"}
<< {"ok":false,"error":"bad_request","reason":"secret_exists","message":"secret already exists (overwrite to replace)"}
```

### `delete`

`{"v":1,"op":"delete","name":"tmp/x"}` gives `{"ok":true,"audit_id":"11"}` or `not_found` / `secret_not_found`. Not presence-gated.

### `show`

Request fields: `name`, and `caller` and `cwd` (displayed in the prompt). The daemon asks the human on every call (grants are neither consulted nor created), writes the audit row **before** sending the value, and does not send the value if that write fails. Success:

```json
{"ok":true,"audit_id":"12","result":{"value":"..."}}
```

This is the only response in the protocol that carries a secret value. The daemon cannot tell whether the client is a terminal; the "TTY only" rule is applied by the CLI before it sends the request. The MCP shim never sends this op.

### `run`

Fields: `argv`, `secrets`, `cwd`, optionally `caller`, `env_prefix`, `timeout_s`. The sequence is described in [README.md](README.md) ("How a run is decided"). Output frames stream while the command runs; then one final response.

A command that ran, with a non-zero exit (note stderr arrived first):

```
>> {"v":1,"op":"run","caller":"claude-code","cwd":"/home/me/proj","argv":["sh","-c","echo key=$API_KEY; echo oops >&2; exit 3"],"secrets":["API_KEY"],"timeout_s":60}
<< {"stream":"stderr","data":"oops\n"}
<< {"stream":"stdout","data":"key=[REDACTED:API_KEY]\n"}
<< {"ok":true,"exit_code":3,"audit_id":"7"}
```

A command that exceeded `timeout_s` (killed with SIGTERM to its process group, then SIGKILL after 2 seconds):

```
>> {"v":1,"op":"run","caller":"claude-code","cwd":"/home/me/proj","argv":["sleep","5"],"secrets":["API_KEY"],"timeout_s":1}
<< {"ok":true,"exit_code":124,"audit_id":"9","reason":"timeout"}
```

A denial (no command was started):

```
>> {"v":1,"op":"run","caller":"claude-code","cwd":"/home/me/proj","argv":["printenv","API_KEY"],"secrets":["API_KEY"]}
<< {"ok":false,"audit_id":"10","error":"denied","reason":"user_denied"}
```

A refusal by naming a secret that does not exist:

```
>> {"v":1,"op":"run","caller":"claude-code","cwd":"/home/me/proj","argv":["true"],"secrets":["nope"]}
<< {"ok":false,"audit_id":"9","error":"not_found","reason":"secret_not_found","message":"vault: secret not found: nope"}
```

Notes:

- `exit_code` is the command's own status, `128+N` if a signal killed it, `124` on timeout, `127` if `argv[0]` was not found (with `message` "command not found: ..."), `126` if it could not be executed. If the process could not be started at all the response is `failed` / `internal` with no `exit_code`.
- A failure while resolving the secrets (for example one vanished between approval and release) is answered with the `error` and `reason` it would have had and leaves one `error` audit row. If the process cannot be started after the `released` row was written, the response is `failed` / `internal` with `message` "command could not be started: ..." and the log gets a `completed` row whose reason starts `not started:`.
- If the client disconnects, the command is stopped and the daemon tries to send `failed` / `canceled` to whoever is left.
- Environment variable names are derived by the daemon from the secret names (last path segment, uppercased; full name on collision); the request does not carry an environment.

### `grants`

```
>> {"v":1,"op":"grants","action":"list"}
<< {"ok":true,"result":[]}
```

`list` returns the active (unexpired) grants as `[{id, caller, cwd_prefix, secrets, cmd_prefix, expires_at, uses_remaining?, created_at}]`. `revoke` with `grant_id` answers `{"ok":true,"grant_id":"..."}` or `not_found` / `grant_not_found`. `revoke_all` answers `{"ok":true}`. Not presence-gated.

### `audit`

```
>> {"v":1,"op":"audit","action":"verify"}
<< {"ok":true,"result":{"ok":true,"entries":9}}
>> {"v":1,"op":"audit","action":"list","limit":2}
<< {"ok":true,"result":[{"id":"9","ts":"2026-10-25T14:03:04.312789Z","caller":"claude-code","cwd":"/home/me/proj","argv":["sleep","5"],"secrets":["API_KEY"],"decision":"completed","exit_code":124,"duration_ms":1004,"reason":"timeout"},{"id":"8","ts":"2026-10-25T14:03:04.312789Z","caller":"claude-code","cwd":"/home/me/proj","argv":["sleep","5"],"secrets":["API_KEY"],"decision":"allowed_once","reason":"released"}]}
```

- `list`: newest first; each element `{id, ts, caller, cwd, argv, secrets, decision, grant_id?, exit_code?, duration_ms?, reason?}`. `decision` is one of `allowed_grant`, `allowed_once`, `allowed_new_grant`, `completed`, `denied_user`, `refused_policy`, `refused_tier`, `error`.
- `verify`: `{ok, entries, first_bad_id?}`. `ok:false` means the chain is broken at `first_bad_id` (the response itself is still `ok:true`; the CLI exits 1).
- `export`: `{"csv":"..."}`, all rows oldest first. Answers `failed` / `internal` if the CSV would exceed 1 MiB.

### Errors on any op

```
>> {"v":1,"op":"bogus"}
<< {"ok":false,"error":"bad_request","reason":"unknown_op"}
>> {"v":2,"op":"list"}
<< {"ok":false,"error":"bad_request","reason":"unsupported_version"}
```

Before the vault exists, every op except `status` answers `failed` / `vault_not_initialized` with the message "vault not initialized; run grantd init". If the vault exists but cannot be opened (wrong key store, bad permissions), the answer is `failed` / `internal` with the message "vault could not be opened (see daemon log)".

## Compatibility

The protocol is version 1 and the daemon rejects any other `v`. The result types in `internal/proto/result.go` are documented there as extendable additively (new optional fields only), and `Response.Message` is for display only, so clients should ignore fields they do not know, branch on `error` and `reason`, and treat a reason they do not recognise by its category.
