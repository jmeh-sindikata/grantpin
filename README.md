# grantpin

grantpin is a local secrets broker for AI coding agents on macOS. It lets an agent such as Claude Code run a command that needs credentials (an API key, a database URL) without the agent ever receiving the credential. You keep your secrets in an encrypted vault on your Mac. The agent asks to run a command with named secrets, grantpin shows you the exact command and asks for Touch ID, and only then runs it. It is for developers who use coding agents and do not want API keys in a `.env` file, in the chat history or in the model provider's logs. Local only: no cloud, no account.

Website: <https://jmeh-sindikata.github.io/grantpin-web/>

## Install

With Homebrew:

```sh
brew install --cask jmeh-sindikata/grantpin/grantpin
```

Then open grantpin from Applications (step 2 below). Update with `brew upgrade --cask grantpin`.

Or download the latest DMG from the [releases page](https://github.com/jmeh-sindikata/grantpin/releases/latest). It is a universal (Apple Silicon and Intel), Developer ID signed and notarized build for macOS 14 or later.

1. Open the DMG and drag grantpin to Applications.
2. Open grantpin from Applications. It lives in the menu bar; there is no Dock icon.
3. The Welcome window walks you through creating the vault, installing the background service, adding a first secret and connecting Claude Code.

There is no auto-update yet: to update, run `brew upgrade --cask grantpin`, or download the new DMG and drag the app over the old one. Your vault is in `~/Library/Application Support/grantpin` and is not touched.

## Connect Claude Code

The app's Connect screen shows this command (the path is where the app is installed; this is the usual `/Applications` one). Run it in a terminal:

```sh
claude mcp add --scope user grantpin -- /Applications/grantpin.app/Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin mcp
```

Then restart Claude Code, or run `/mcp`, and ask it: "Use grantpin's secret_list tool and tell me the names of my secrets." It sees names only. To see an approval, ask it to run a command that uses one of them. For a single project instead of every project, drop `--scope user` and run it in that project's folder.

## How it works

- Your secrets live in a local vault (an encrypted SQLite file). The vault key is wrapped by a Secure Enclave key, so it cannot be copied to another machine.
- The agent never gets a value. It can list names, and it can ask to run a command with some of them injected as environment variables.
- Every release is approved: a dialog shows the exact command and the secrets it would get, and Touch ID confirms. You can also approve a time-limited standing grant for a folder and command prefix, and revoke it later.
- The approved command runs with the secrets in its environment. Its output comes back to the agent with each injected value replaced by `[REDACTED:NAME]`, and every request and decision is written to a tamper-evident audit log.

## Security

grantpin narrows what an agent can do with your secrets; it is not a sandbox. Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the full analysis. In short, it does not protect against:

- **An approved command that exfiltrates.** If you approve a command that sends the key somewhere, grantpin cannot tell. You are the control: read the command in the dialog. There is no sandbox and no network egress control.
- **Malware running as you.** Human presence is enforced by the daemon's own logic, not by cryptography on the key. Code with full control of your account can replace the binary, delete the vault or tamper with the service. A vault created with the Keychain fallback (a build that cannot use the Secure Enclave) has a key readable by anything running as you.
- **Everything the agent could do around the gate.** Redaction is an exact match of the value, so a command that prints it base64-encoded gets through. Storing, overwriting and deleting secrets are not behind Touch ID, so a same-user process can destroy or replace them.

## Build from source

You need macOS 14 or later, Go 1.27 or newer, and Xcode (the app is built with `xcodebuild`; the Touch ID and Secure Enclave code use cgo).

```sh
make ci     # Go: build, vet, staticcheck, tests (also with the dev tag), coverage
make app    # dist/grantpin.app, unsigned: SwiftUI app plus the Go helper inside it
```

A from-source build is not signed with a provisioning profile, so it cannot use the Secure Enclave and falls back to a Keychain-held key. [docs/RELEASE.md](docs/RELEASE.md) describes how the signed, notarized DMG is made. [docs/README.md](docs/README.md) is the detailed manual: install from source, the `grantpin` command line, policy files, grants and the audit log.

## Renamed from grantd

grantpin was called grantd until v0.2.0, which shipped as grantd. There is no automatic migration: the new app uses its own bundle identifier (`dev.grantpin.app`), launchd label, data directory, Keychain key and environment variables (`GRANTPIN_*`), so the two never share state. To move over, remove the grantd install with its own Settings, Uninstall (tick everything), then install grantpin and add your secrets again. The on-disk formats are not compatible either: the vault, audit log and grants use grantpin-specific encryption and MAC domain tags, so a grantd vault cannot be opened by grantpin.

## Status

v0.2, macOS only, early software. The CLI, the daemon and the menu-bar app work; a Linux and a Windows backend and auto-update are not done. Homebrew works through a [personal tap](https://github.com/jmeh-sindikata/homebrew-grantpin); the official homebrew-cask is not done. Known gaps and planned work are in [docs/BACKLOG.md](docs/BACKLOG.md). Other docs: [docs/PROTOCOL.md](docs/PROTOCOL.md) (the daemon's socket protocol) and [docs/MANUAL-TEST-MACOS.md](docs/MANUAL-TEST-MACOS.md) (hardware test checklist).

## License

[Apache-2.0](LICENSE).
