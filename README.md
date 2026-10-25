# grantd

A local secrets broker for AI coding agents. The agent asks to run a command with named secrets; grantd shows you the exact command, asks for Touch ID, runs it with the secrets in its environment and returns redacted output. No operation returns a secret to the agent. macOS only in v0.1; Apache-2.0.

**Read [docs/README.md](docs/README.md)**: it has what grantd does and does not protect against, install, the five-minute path from `grantd init` to a Touch ID-gated run through Claude Code, and the CLI reference.

- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md): assets, trust boundaries, attacker models, and the limits (including that grants in the vault file are not authenticated).
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the daemon's socket protocol.
- [docs/MANUAL-TEST-MACOS.md](docs/MANUAL-TEST-MACOS.md): hardware test checklist.
- [docs/BACKLOG.md](docs/BACKLOG.md): deferred work.

```sh
make build && install -m 0755 bin/grantd ~/.local/bin/grantd
grantd init && grantd service install && grantd set API_KEY
claude mcp add grantd -- grantd mcp
```
