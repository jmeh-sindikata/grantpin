# grantd MCP shim

`grantd mcp` runs a stdio MCP server that translates four tool calls into daemon
socket requests. It is a thin shim: policy, grants, approval prompts, redaction
and audit all happen in the daemon.

## Tools (names fixed)

| Tool | Args | Returns |
|---|---|---|
| `secret_list` | none | `{secrets: [{name, tags, url, expires_at, min_tier}]}` (no values, no notes) |
| `secret_exists` | `name` | `{exists}` |
| `secret_masked` | `name` | `{masked}` (`****WXYZ`; fully masked under 12 chars) |
| `secret_run` | `argv[]`, `secrets[]` (both required), `cwd?` (absolute), `timeout_s?` | `{exit_code, stdout, stderr, grant_id}` |

There is deliberately no tool that returns a secret value, and no `show`, `set`,
`delete` or `grants` over MCP. `TestSourceNeverReferencesShow` fails if this
package ever mentions the show op or its result type.

Daemon refusals (`denied`, `refused`, `not_found`, ...) come back as MCP tool
errors (`isError: true`) with text like `denied: user_denied`, never as protocol
errors. `stdout`/`stderr` are already redacted by the daemon and are capped at
1 MiB each with a truncation marker.

`caller` is the MCP client name from the initialize handshake, lowercased, with
anything outside `[a-z0-9_.-]` replaced by `_`, at most 64 chars, `mcp` if empty.
`cwd` defaults to the shim's own working directory (Claude Code starts MCP
servers in the project directory); a relative `cwd` is rejected.

If the daemon is not running the shim spawns `grantd daemon --socket <path>`
once (detached, own session, stdio on /dev/null, minimal environment), waits up
to 5s for the socket, and retries. If that fails the tool returns:
`grantd daemon is not running; run `grantd daemon` or `grantd service install``.
Prefer `grantd service install` so the daemon starts at login.

## Claude Code configuration

No password and no environment variables belong in this config:

```json
{"mcpServers":{"grantd":{"command":"grantd","args":["mcp"]}}}
```

Or from a shell: `claude mcp add grantd -- grantd mcp`. A custom socket is
`--socket PATH` or `GRANTD_SOCKET` (set in the shell that starts `claude`, not in
the MCP config).

## How to test with Claude Code

1. `grantd init`, then `grantd set API_KEY` (value from stdin).
2. `grantd service install` (or run `grantd daemon` in another terminal).
3. Register the server (above) and start `claude` in a project directory.
   `/mcp` should show `grantd` connected with four tools.
4. Ask: "list my grantd secrets" (no prompt), then "run `printenv API_KEY` with
   API_KEY via grantd". The native approval prompt appears; after approval the
   output must show `[REDACTED:API_KEY]`, never the value.
5. Stop the daemon and repeat step 4 to see auto-start (or the clear error if
   the `grantd` binary cannot start it).
6. Without Claude Code: pipe JSON-RPC into `grantd mcp`, e.g. the MCP Inspector:
   `npx @modelcontextprotocol/inspector grantd mcp`.

Logs go to stderr only (stdout is the protocol channel) and contain op names,
never tool arguments.
