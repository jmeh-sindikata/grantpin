# grantd v0.2: menu-bar app spec

> **Status (2026-10-26): v0.2 step 3b done (the remaining screens); step 3a (the menu-bar popover and the Secrets window) was done before it. The owner accepted every default in section 8.** Steps 1 and 2 (G1 to G4, the nested helper bundle, `GrantdKit` as a complete typed client, `DaemonMonitor`, the `.env` import runner, the display-text sanitiser) are as described in the work breakdown. Step 3a adds, in `GrantdKit`: the name, tag, url, notes and value validators (`Validators`, parity-tested against the dev daemon), the expiry parser and formatter (`ExpiryParser` matches `grantd set --expires`, tested against the CLI), audit pairing with the 3.4 labels (`AuditPairing`), the 3.0 error mapping and the confirmation texts of 3.2 (`UserMessage`, `Confirmation`), `StatusLine`, `MenuBarIcon`, the view models (`SecretFormModel`, `SecretsViewModel`, `ImportViewModel`, `PopoverModel`, all driven through fakeable service protocols), `HelperLocator`, `PathDetector` and `HelperActions`. In the app: the popover (status line with the four states, counts, TAMPERED warning, the last three events, Open Secrets, Open Activity, Settings, Quit, and the Start and Create vault buttons), the Secrets window (table, search, sort, detail inspector with the on-demand `masked` check, Add / Edit details / Replace value sheet, delete, Import .env with a dry-run preview, empty state, banners, monitor-driven disabled state) and placeholder Activity and Settings windows (replaced in 3b). **Start** runs `grantd service install --exe <outer grantd.app> --path <PATH>` through the helper (the one way the app starts the daemon); the outer app path is passed and G1 resolves it to the helper binary, instead of the explicit helper path of 2.5. **Create vault** runs `grantd init`. `make ci-app` ran 264 Swift tests against the dev daemon at that step. **Step 3b adds**, in `GrantdKit`: `GrantsViewModel` and `StandingGrantFormModel` (command tokenizer, secret patterns with brace-aware splitting, lifetime presets capped at 90 days, the plain-language summary, one cancellable `grants add` that never retries, the 3.3 outcome mapping, the shell and interpreter "I understand" tick), `ActivityViewModel` (pairing, filters, search, Load more that stops at `truncated`, Verify and the export outcome), `ServiceStatus` (the `service status` parser, exit 3 = not installed), `ServiceDiagnosis` and `ServiceWatcher` (the down states of 2.5 and "keeps stopping": three pid changes in 60 s), `SettingsModel`, `SecurityFacts`, `UninstallModel` (staged, never deletes a vault while the daemon answers), `OnboardingModel` (state-derived steps, the weaker-protection retry), `ConnectSnippets` (shell quoting and JSON escaping, tested through a real `/bin/sh`), `ConnectionTest`, `AppLocation` and the popover's new buttons (Repair, Restart, Review, Set Up, Open Logs Folder) and secrets quick list; `HelperActions` also runs `service status`, `service uninstall`, `--version` and `init --keychain-fallback`. In the app: the Grants window (badges, time left, revoke, revoke all, the tampered row), the "New standing grant" sheet, the Activity window, Settings (General, Connect, Security & Data, Uninstall), the Welcome window, "Grants (n)...", Review, the quick list and the Updated column, the location check with "Move to Applications and Relaunch", the second-launch handling and `Localizable.xcstrings`. `make ci-app` runs 433 Swift tests, among them dev-daemon tests of the Grants window (a standing grant through the form with the allow approver, list, revoke, revoke all, a forged row shown as tampered, a policy refusal and ceiling) and of the Activity window (a real run paired into one event, a log too big for one page, verify, a tampered log, export).

**Step 3b leaves open:** nothing was opened on a screen; the screens were compiled and rendered offscreen against the dev daemon, and the Table-with-inspector windows (Secrets, Activity) do not draw their rows in an offscreen render, so their first real look (Tables, toolbars, the segmented filter, sheets, the Settings tabs, activation policy, Cmd-N and Cmd-F) is the owner's. Every flow that needs the signed bundle (Install Service, Create Vault, Repair, Move to Applications, the login item, Uninstall, `SMAppService`) is untested end to end and is in MANUAL-TEST-MACOS.md section 8. Not built: the custom socket path offered when the account name makes the default socket path too long (the screens only say so), XCUITest, and a way to keep `Localizable.xcstrings` current from `xcodebuild` (Xcode keeps it in step, a command-line build does not; strings from `GrantdKit` such as `UserMessage` and `Confirmation` are English constants and not in the catalog). "Move to Applications" copies the app and leaves the original, because a translocated or disk-image copy cannot be moved. Deleting the vault always stops the service first, and Uninstall also removes the app's own login item.

Status: design spec, no code. Audience: the agent that implements v0.2 and the owner who reviews it. Written against the tree at commit `d1675b5` (plus uncommitted work in `internal/grant` and `internal/audit` that nothing here depends on). File references are to this repository; protocol names are exactly those in [PROTOCOL.md](PROTOCOL.md).

Decisions in this document are made; the six open questions in section 8 each carry a default so work can start without answers. Where a fact was checked on this machine (macOS 27.0.1, Xcode 27.1, SDK 27.0, Go 1.27.3) it says so; what could not be checked is collected in Appendix A.

## 0. Summary of the decisions that matter most

1. **The Go daemon/CLI cannot be a bare second executable in the bundle.** I tested it: a Go binary signed with the project's entitlements and placed at `Contents/MacOS/grantd` or `Contents/Helpers/grantd` next to a different main executable is killed at launch (exit 137, amfid: `No matching profile found`). The same binary inside its own nested bundle `Contents/Helpers/grantd-daemon.app/` with a copy of the provisioning profile launches, and `grantd init` prints `keystore tier: hardware`. So the layout is: SwiftUI app is the outer bundle's main executable; the Go binary is the main executable of a nested helper bundle. Section 2.1.
2. **The app is a client of the socket and nothing else.** It never touches the Keychain, never reads a secret value back, never answers an approval prompt. The daemon keeps osascript + Touch ID for v0.2.
3. **A few small Go-side changes are prerequisites or strongly recommended** (section 2.8): the service layer must find the helper bundle, the standing-grant dialog sentence must stop saying "you just ran `grantd grants add`", and metadata-only edit needs a new `update` op (otherwise editing a tag means retyping the secret).
4. **Xcode project checked in under `app/`, logic in a local Swift package `app/GrantdKit`** so the protocol client and its tests run with plain `swift test`, no signing, no Xcode GUI.

## 1. Goals and non-goals for v0.2

### Goals

A person who never opens a terminal can do all of this from the app:

| # | Task | Screen | Protocol / mechanism |
|---|---|---|---|
| 1 | Install: drag `grantd.app` to Applications, open it, be guided | Onboarding | `service install` via helper |
| 2 | Create the vault | Onboarding | helper `init` (not a protocol op) |
| 3 | Add, replace, delete secrets; edit tags/URL/notes/expiry | Secrets | `set`, `delete`, `list`, `masked`, `update` (new, see 2.8) |
| 4 | Import a `.env` file, with conflict handling and a dry-run preview | Secrets | helper `import` |
| 5 | See active grants, revoke one or all | Grants | `grants` `list`/`revoke`/`revoke_all` |
| 6 | Create a standing grant (the daemon asks for confirmation itself) | Grants | `grants` `add` |
| 7 | Read the audit log, verify it, export CSV | Audit | `audit` `list`/`verify`/`export` |
| 8 | See daemon status; start or repair it | Menu bar, Settings | `status`; helper `service` |
| 9 | Start at login | Settings | `service install`; `SMAppService.mainApp` |
| 10 | Connect Claude Code: show the exact `claude mcp add` command and the `.mcp.json` snippet, each with a copy button | Onboarding, Settings | none (text) |
| 11 | Uninstall everything, optionally including the vault | Settings | `service uninstall`, file removal |

Also required: the signed bundle keeps the Secure Enclave working (`keystore tier: hardware`), and the live install (`~/Applications/grantd.app`, team `MT2QHQX6PS`, Apple Development identity plus macOS App Development profile) can be upgraded in place by the app's "Repair" action.

### Non-goals (v0.2)

- **No reveal button, no `show`.** Section 4.2 says why.
- **No in-app approval.** Dialogs stay in the daemon (osascript chooser, then LocalAuthentication). Section 4.7 describes v0.3.
- **No test-run of a command** (`run` is not used by the app), no policy (`.grantd.yml`) editor, no per-run "Allow for N" configuration.
- **No automatic detection of whether Claude Code is connected.** The daemon does not know its clients, and reading `~/.claude.json` is another tool's private state. The Connect panel shows the command and a test prompt.
- **No "Run it for me" button for `claude mcp add`.** Finding the user's `claude` binary and its PATH from a GUI process is a source of opaque failures; a copy button is enough for now.
- **No notarization, DMG or auto-update.** The Makefile signing path stays parameterised (`IDENTITY`, `PROFILE`, `TEAM_ID`) so Developer ID can be dropped in later (open question 1).
- **No network access of any kind.** No analytics, no update check, no crash upload.
- **No Linux/Windows UI**, no iOS, no multiple vaults, no secret sharing, no cloud.
- **No localisation.** All strings are English, kept in one String Catalog so a later pass can translate them.

## 2. Architecture

### 2.1 Bundle layout and why

What exists today (`make bundle`, `build/bundle/Info.plist`): `Contents/MacOS/grantd` is both the main executable and the daemon, signed with `com.apple.application-identifier = MT2QHQX6PS.dev.grantd.app` and `keychain-access-groups = [MT2QHQX6PS.dev.grantd]` (verified with `codesign -d --entitlements -` on `~/Applications/grantd.app`; flags `runtime`).

After v0.2:

```
grantd.app/
  Contents/
    Info.plist                          CFBundleIdentifier dev.grantd.app
                                        CFBundleExecutable grantd-app, LSUIElement, min macOS 14.0
    embedded.provisionprofile           same profile as today
    MacOS/
      grantd-app                        the SwiftUI app (main executable)
    Helpers/
      grantd-daemon.app/                nested helper bundle
        Contents/
          Info.plist                    CFBundleIdentifier dev.grantd.app.daemon
                                        CFBundleExecutable grantd, LSBackgroundOnly
          embedded.provisionprofile     a copy of the same profile
          MacOS/
            grantd                      the Go binary (daemon, CLI, MCP shim)
    Resources/                          Assets.car, Localizable.xcstrings, AppIcon
```

Both bundles are signed with the same Apple Development identity, `--options runtime`, and the same entitlements file (`build/bundle/grantd-app.entitlements`, expanded by `make sign-bundle`). Only the helper uses `keychain-access-groups`; sharing the file keeps one signing recipe and costs nothing now (re-evaluate for v0.3, section 4.7).

**Why a nested bundle and not a plain executable (tested, not assumed).** On this machine I copied the live bundle, replaced the main executable with a trivial one, and put the Go binary (signed with the project entitlements, same identity) in each candidate place:

| Placement of the Go binary | Result |
|---|---|
| `Contents/MacOS/grantd` beside another main executable | killed at launch, exit 137 |
| `Contents/Helpers/grantd` | killed at launch, exit 137 |
| `Contents/Helpers/<x>.app/Contents/MacOS/grantd` with a copy of the profile, bundle id `dev.grantd.app` | runs; `GRANTD_HOME=<tmp> grantd init` prints `keystore tier: hardware` |
| same, bundle id `dev.grantd.app.daemon` | same result |

The unified log for the first two says `amfid: ... not valid: ... Code=-413 "No matching profile found"` and `Code has restricted entitlements, but the validation of its code signature failed`. Reading: the provisioning profile that authorises restricted entitlements (`keychain-access-groups`) is looked up for a bundle's main executable; a non-main plain executable has no profile and is refused. `codesign --verify --deep --strict` passed for the nested layouts. This is the reason for the structure above, and it is why "put the Go binary in `Contents/MacOS` or `Contents/Helpers`" (the two options in the brief) are both rejected. `Contents/Helpers` as the parent directory is kept because codesign's default resource rules (`CodeResources` in the live bundle) already treat `Helpers/` as nested code.

Consequences:

- **launchd** runs `…/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd daemon` directly (ProgramArguments, as `internal/service/plist.go` writes it). No LaunchServices involvement; the kernel path that I tested is the same one.
- **Executable names:** the Swift executable is `grantd-app` and the Go one stays `grantd`, so process lists and crash reports tell them apart. `internal/service/service.go` `bundleExe` resolves a `.app` through `CFBundleExecutable` of the *outer* bundle, which is now the Swift binary; that is why change G1 is needed. 
- **Signing order** is inside-out: helper bundle first, then the outer bundle, without `--deep` (section 5.3).
- **Two bundle identifiers** (`dev.grantd.app`, `dev.grantd.app.daemon`) are used with one profile. This worked with the current Apple Development profile (which carries `MT2QHQX6PS.*`-style group access per the owner); it has not been tried with a Developer ID profile (Appendix A).
- **Do not use `SMAppService.agent(plistName:)` for the daemon.** It would remove the hand-written plist, but its plist is static inside the bundle and cannot record the user's PATH, and the CLI path (`grantd service install`) must keep working for people who never install the app. One mechanism: `service install`.
- **Migration of the live install.** The launchd plist currently names `…/grantd.app/Contents/MacOS/grantd`; after the upgrade that file no longer exists. The app detects this (`service status` prints `warning: executable no longer exists`, and `Status.ExeMissing` is true) and offers "Repair" which re-runs `service install` with the new path. The `claude mcp add` registration also names the old path and breaks; the Connect panel shows the new command and the one-liner `claude mcp remove grantd` to run first.

### 2.2 Processes and IPC

```
 ┌───────────────────────── grantd.app (user session) ─────────────────────────┐
 │                                                                             │
 │  grantd-app (SwiftUI, no sandbox)                                           │
 │   ├─ GrantdKit.Client ──────── one Unix-socket connection per request ──┐   │
 │   │                                                                     │   │
 │   └─ Process (spawn, own env) ──► grantd-daemon.app/…/grantd            │   │
 │        init | import | service install/uninstall/status | --version     │   │
 │        (short-lived; never `daemon`, never `mcp`)                       │   │
 └─────────────────────────────────────────────────────────────────────────┼───┘
                                                                           │
   launchd (LaunchAgent dev.grantd.daemon, Aqua) ──starts──►  grantd daemon ◄┘
                                                              │  ~/Library/Application Support/grantd/grantd.sock (0600, same-UID)
   Claude Code ──spawns──► grantd mcp ──one request per call──┘
                                                              │
                                  osascript chooser ◄─────────┤ policy → grants → approver
                                  LocalAuthentication ◄───────┘ → keystore (Secure Enclave) → audit
```

Who does what:

| Concern | Owner | Notes |
|---|---|---|
| Create the vault | the helper's `grantd init`, spawned by the app | Only the helper (inside the signed bundle, with the profile) may touch the Secure Enclave key (`dev.grantd.vault-kek`). `init` is a CLI verb, not a protocol op; the running daemon opens the new vault without a restart (README, `grantd daemon`). |
| Start the daemon | launchd, always | The app never runs `grantd daemon`. It installs or repairs the job with `grantd service install --exe <helper path> --path <PATH>`. The MCP shim's own auto-start is a fallback and stays untouched. |
| Secrets / grants / audit / status | the daemon | The app speaks the socket protocol only. |
| Approval dialogs, Touch ID | the daemon | Unchanged. The app can be closed or crashed while a prompt is on screen. |
| Claude Code to daemon | `grantd mcp` spawned by Claude Code | The app is not involved at runtime. |

### 2.3 Finding the socket

Resolution order in the app (a Finder-launched process has none of the user's shell environment, and the launchd job defines only `PATH` and optionally `GRANTD_SOCKET`):

1. `GRANTD_SOCKET` in the app's own environment. Used by tests and by the development scheme (section 5.5). When set, the app is in **development mode**: service install/uninstall, vault init, uninstall-everything and the login-item toggle are disabled, with a banner "Development socket: <path>". This stops a debug build from touching the real launchd job.
2. `EnvironmentVariables.GRANTD_SOCKET` in `~/Library/LaunchAgents/dev.grantd.daemon.plist`, if the file exists and defines it (parsed with `PropertyListSerialization`; this is the only file the app reads that it did not write).
3. `~/Library/Application Support/grantd/grantd.sock`, built from `FileManager.homeDirectoryForCurrentUser`.

`XDG_RUNTIME_DIR` is not consulted (it is never set for a launchd GUI job or a Finder app). The path must be at most 103 bytes (`internal/daemon/socket.go`); if the default exceeds it (very long account name) the app shows "Your account name is too long for grantd's default socket path" and offers a custom path via `service install --socket`, stored in the plist (so rule 2 finds it). The socket path shown in Settings comes from `status.socket` when reachable, else the resolved path.

### 2.4 One request per connection: what it means for the UI

The daemon closes the connection after one final response (PROTOCOL.md "Transport"). Therefore:

- `GrantdKit.Client.call(_:)` opens a new `AF_UNIX` stream socket per request, writes one line, reads stream frames and exactly one final response, closes. A `Client` value is stateless and `Sendable`; there is no connection pool and no long-lived connection. Use POSIX `socket/connect/write/read` on a background task (simple, and no half-close surprises). **Never `shutdown(SHUT_WR)`**: the daemon treats any read result including EOF as "client went away" and cancels the request.
- Line limit: build the request line, and if it is above 4 MiB (`MaxLineBytes`) fail locally with "value too large" before connecting. A 1 MiB value of control characters JSON-escapes to 6 MiB; the local check matters.
- **Polling.** There is no push channel. `status` is polled; lists are refreshed on demand.

| What | When | Interval |
|---|---|---|
| `status` | popover open or any app window key | every 3 s |
| `status` | app running, nothing visible | every 30 s |
| `status` | daemon unreachable | every 3 s while visible, else every 15 s; plus `service status` (helper) at the same cadence |
| `list` (secrets) | Secrets window key | on appear, after own mutation, every 10 s (an agent can `set` too) |
| `grants list` | Grants window key, popover open | on appear, after own mutation, every 5 s |
| `audit list` | Audit window key, popover open | on appear, every 5 s |
| anything | system wake (`NSWorkspace.didWakeNotification`) | once, immediately |

Every request is logged by the daemon at INFO, `status` included, into `~/Library/Logs/grantd/daemon.err.log`, and I found no log rotation anywhere in the tree. At the idle 30 s interval that is about 2,900 lines a day. Recommended change G6 (section 2.8) demotes read-only ops to DEBUG; the intervals above are chosen so the app is acceptable without it.

- **Per-op client timeouts** (the daemon's own deadline for `run` is irrelevant here):

| Op | Timeout |
|---|---|
| `status`, `list`, `masked`, `set`, `delete`, `update`, `grants` `list`/`revoke`/`revoke_all`, `audit` `list` | 10 s |
| `audit` `export` | 30 s |
| `audit` `verify` | 60 s (recomputes the whole chain) |
| `grants` `add` | 11 min, cancellable (see 3.3: the daemon waits for the human, up to its 120 s dialog limit plus Touch ID, and its connection deadline is the 1 h cap plus 10 min) |
| connect | 2 s (a local socket either connects or does not) |

Cancelling a request means closing the connection; the daemon cancels the approval (kills the osascript dialog).
- **Concurrency.** At most 4 requests in flight; `grants add` is single-flight (the daemon serialises all approver prompts anyway, so a second `add`, or an agent's run prompt, queues behind the first one's dialog).
- **Mutation then refresh.** After a successful `set`/`delete`/`update`/`grants` write the app re-fetches the affected list immediately; it never edits its cache optimistically.

### 2.5 When the daemon is down

`Client.call` maps `ENOENT`/`ECONNREFUSED` to `DaemonError.notRunning` (as `internal/client` does with `ErrNotRunning`). The monitor then runs `<helper> service status` (exit code 3 means not installed; otherwise it parses `installed/loaded/running/exe/warning` lines, format in `cmd/grantd/cmd_service.go`) and shows one of:

| Situation | Popover headline | Action button |
|---|---|---|
| service not installed (exit 3) | "grantd is not set up to run in the background" | **Start** = `service install` |
| installed, `exe` missing (app moved, replaced, or upgraded layout) | "The background service points to a file that no longer exists" | **Repair** = `service install` |
| installed, not running | "grantd is not running" | **Start** = `service install` (idempotent; it restarts the job) |
| installed, running (pid), socket refuses | "grantd is running but not answering" | **Restart** = `service install`; plus "Open Logs Folder" |
| the job keeps exiting (pid changes between polls, 3 times in 60 s) | "grantd keeps stopping" | "Open Logs Folder" (`daemon.err.log`); no automatic retry |

**Start/Repair/Restart** all run, with the app's environment replaced (section 2.6):

```
<helper> service install --exe <helper path> --path <computed PATH> [--socket <custom>]
```

`--exe` is passed explicitly (the app's own bundle location is known). The shipped app passes the outer `grantd.app` and relies on G1 to resolve it to the helper binary; the explicit helper path above is equivalent. The command waits up to 10 s for the socket (`service.DefaultReadyTimeout`); exit 0 with a `WARNING:` line means launchd started the job but the socket was not ready: show "Started, but grantd has not answered yet" and keep polling. A non-zero exit shows the last 500 characters of stderr, escaped (4.4), in a disclosure.

**Where the app may run from.** `service install` refuses temporary directories (`checkExe`), and a downloaded app that Gatekeeper translocates runs from a randomised read-only path. Before any install the app checks `Bundle.main.bundleURL`: it must be under `/Applications` or `~/Applications`. Otherwise every service/vault action is disabled and the popover says "Move grantd to your Applications folder first" with a button "Move to Applications and Relaunch". The button copies the bundle to a hidden temporary name in the destination folder and renames it into place in one step (`renamex_np` with `RENAME_EXCL`, which also never replaces an existing app), removing the temporary copy on any failure, so a stopped copy cannot leave a broken `grantd.app`. The app then starts the copy and quits itself only if the process it got back is a different one; with `LSMultipleInstancesProhibited` the system may return the running instance (MANUAL-TEST-MACOS section 8, item 7).

**PATH for the daemon.** The daemon, and every command it runs for an agent, gets only the PATH recorded in the plist (README "Environment of the child process"). A Finder app's PATH is `/usr/bin:/bin:/usr/sbin:/sbin`, so `php`, `node` or `aws` from Homebrew would be "command not found" (exit 127) for a user who never opens a terminal. The app computes the PATH to record:

1. Run `$SHELL -ilc 'printf "__GD_BEGIN__%s__GD_END__" "$PATH"'` and take the text between the markers (rc files may print other output) (5 s timeout, then SIGTERM and, 2 s later, SIGKILL, so a shell that hangs delays the install by at most about 7 s and the fallback PATH is used; stdin `/dev/null`, `$SHELL` validated to be an absolute path to an existing executable listed in `/etc/shells`, else `/bin/zsh`), once per install action.
2. If that fails or is empty: `/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`.
3. Pass it as `--path`. The service layer keeps only absolute entries and drops duplicates (`sanitizePath`).

Settings shows the result in an editable field "Where grantd looks for commands" with a "Re-detect" button and the sentence "Programs that agents run through grantd can only find commands in these folders." Changing it re-runs `service install`. This PATH decides what an approved command resolves to, so it is user-controlled input to a security-relevant setting: the field is plain text, shown in full, and never filled from an agent or a project file.

macOS will probably show a "Background Items Added" notification when the LaunchAgent plist appears (system behaviour for LaunchAgents written by an app since macOS 13; I did not observe it here). The onboarding step mentions it in one sentence.

### 2.6 Subprocess rules (the helper)

The app spawns the helper only for `init`, `import`, `service install|uninstall|status`, `keystore delete`, `--version`. Rules:

- Executable path: `Bundle.main.bundleURL/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd`, resolved once, symlinks rejected, verified to be inside the bundle.
- Environment: `HOME`, `USER`, `LOGNAME`, `TMPDIR`, `LANG`, `PATH=/usr/bin:/bin` and, in development mode only, `GRANTD_SOCKET`. Nothing else (no inherited environment).
- `standardInput`: `/dev/null`, except `import` (below). stdout/stderr captured, each capped at 64 KiB. Timeouts: `init` 30 s, `import` 120 s, `service install` 20 s, `service uninstall`/`status`/`--version` 10 s, `keystore delete` 20 s; then SIGTERM, and SIGKILL 2 s later if the process is still running (an interactive login shell ignores SIGTERM, and Start, Install and Repair must not hang on it). The timeout timer starts before the process does, and cancelling the task takes the same SIGTERM-then-SIGKILL path.
- Never put a secret value in `arguments` or `environment`. (`import` gets the `.env` bytes through an open file descriptor, section 3.2.)
- Exit codes the app interprets: `service status` 3 = not installed. `init` and `import` use 1 for every failure; the app shows stderr, it does not branch on it, with one exception: if `init` fails and stderr contains "Secure Enclave" (case-insensitive) the app offers the weaker-protection retry (3.6). Brittle by nature; a stable error code is backlog (G7).

### 2.7 Application structure (for the implementer)

- `GrantdKit` (Swift package, no UI imports): `Client`, `Request`/`Response`/result models (`Codable`, snake_case keys, unknown fields ignored), `DaemonError` with `category`, `reason`, `message`, validators (name, tag, expiry, command prefix, TTL), audit pairing, text sanitiser, MCP snippet builder, socket resolver, `.env` report parser, helper runner.
- App target: `AppModel` (`@Observable`, `@MainActor`) owning a `Monitor` (status/service polling) and per-screen models; views are thin. No third-party dependencies (Hardened Runtime and library validation stay on, section 4.5).
- Windows: `MenuBarExtra(...).menuBarExtraStyle(.window)` for the popover; `Window("Secrets", id: "secrets")`, `Window("Grants", id: "grants")`, `Window("Activity", id: "audit")`, `Window("Settings", id: "settings")` (a `Settings { }` scene cannot be opened from a menu-bar app on macOS 14+; the popover row and Cmd-, call `requestWindow`), onboarding as a `Window("Welcome", id: "onboarding")`. Activation policy: start `.accessory`; switch to `.regular` and activate when any window opens; back to `.accessory` when the last closes. `LSMultipleInstancesProhibited` is true; a second launch activates the first and opens the Secrets window.
- State persisted in `UserDefaults`: `onboardingDone`, window frames, last-used standing-grant TTL (only if it is one of the presets; a custom or unrecognised value gives the 30-day default), "show activity in popover". `UserDefaults` is writable by any program running as the user, so nothing in it may widen what a form proposes: the standing-grant folder is never remembered (the form always opens with no folder, and a value left by an older version is deleted). **Never persisted:** anything typed into a value field, notes, or a pasted `.env` path's contents. No `@SceneStorage`. Windows are marked non-restorable.

### 2.8 Changes needed in the Go tree

The app is a client of the existing protocol, with these exceptions. Each is small and listed with the step that needs it (section 7).

| ID | Change | Why | Required? |
|---|---|---|---|
| G1 | `internal/service` `bundleExe`: when a `.app` contains `Contents/Helpers/grantd-daemon.app`, resolve to its `Contents/MacOS/<CFBundleExecutable>`; otherwise keep today's behaviour. Add tests next to `bundle_test.go`. | Without it `grantd service install --exe /Applications/grantd.app` (README, MANUAL-TEST §2c(f)) would resolve to the Swift binary and install a job that runs the UI with the argument `daemon`. The app itself passes the explicit inner path and does not need G1. | Required (CLI users, docs) |
| G2 | Makefile and `build/bundle`: new layout, helper Info.plist template, Go built with `CGO_CFLAGS=-mmacosx-version-min=14.0 CGO_LDFLAGS=-mmacosx-version-min=14.0`, `MIN_MACOS=14.0` pinned. | Today `make bundle` takes `LSMinimumSystemVersion` from the Go binary's `LC_BUILD_VERSION`. On this machine that is `27.0` (verified with `otool -l bin/grantd`); with the flags it is `14.0` (verified). Without the flags the helper does not start on macOS 14 to 26. Another agent is editing the Makefile now; rebase on it. | Required |
| G3 | `internal/approve/darwin/reason.go` `StandingText`: replace the last sentence "Only continue if you just ran `grantd grants add` yourself." with "Only continue if you just asked for this yourself." (and the same in the Touch ID reason if it repeats it; update `reason_test.go`, README "Standing grants", THREAT-MODEL 4.7). | The app triggers this dialog; a sentence that names a CLI command the user never typed is wrong and trains people to ignore it. Do not make the text depend on the `caller` string: it is untrusted and an agent could pick it. | Strongly recommended (default yes, open question 3) |
| G4 | New op `update`: fields `name`, optional `tags`, `url`, `notes`, `expires`, `min_tier` and a `clear` list. No `value`. Same validation as `set`; `not_found`/`secret_not_found` if absent; not presence-gated (same class as `set`) except that lowering `min_tier` asks the human (`KindLowerTier`); audit row `allowed_once`, reason `update` (`update: lower min_tier` for an approved lowering). Additive protocol change. | Today `set` needs a non-empty value, so the only way to fix a tag is to retype the secret, which the app cannot read back. `min_tier` is bound into the GCM additional data, so changing it re-encrypts the value, and lowering it must never be a silent metadata edit. New capability for an agent: it can clear or change an expiry without knowing the value. It could already replace the value; I judge it the same trust class as `set`. | Recommended (default yes, open question 2); fallback is "Replace value" only |
| G5 | `grantd import --caller NAME` (default `cli`), passed to each `set`. | Audit rows for imported secrets would otherwise say `cli` instead of `grantd-app`. | Optional |
| G6 | Log `status`, `list`, `exists`, `masked`, `grants list`, `audit list` at DEBUG. | Polling noise in an unrotated log. | Optional |
| G7 | Stable machine-readable results: `grantd import --json`, distinct exit code for "Secure Enclave unavailable" in `init`. | Removes the text parsing in 2.6 and 3.2. | Backlog (v0.2.1) |

## 3. Screens

### 3.0 Shared rules

**Error mapping.** Every failure is a `DaemonError(category, reason, message)`. The UI branches on `reason`, falls back to `category`, and shows `message` (already redacted by the daemon, display only) in smaller text under the headline.

| `reason` (category) | Headline shown |
|---|---|
| `vault_not_initialized` (failed) | "Create your vault first." with button "Set Up…" |
| `secret_exists` (bad_request) | "A secret with this name already exists." |
| `secret_not_found` (not_found) | "That secret no longer exists." (then refresh) |
| `grant_not_found` (not_found) | "That grant is already gone." (then refresh) |
| `user_denied` (denied) | "You cancelled the confirmation." |
| `approver_unavailable` (denied) | "grantd could not show the confirmation dialog. Make sure you are logged in at this Mac and have a device password, then try again." |
| `policy_refused` (refused) | "A .grantd.yml file in that folder does not allow this." + `message` |
| `tier_unmet` (refused) | "This secret needs a stronger protection level than this vault provides." + `message` |
| `secret_expired` (refused) | "That secret has expired." |
| `bad_request` (bad_request) | "grantd rejected the request:" + `message` |
| `unsupported_version` (bad_request) | "This app and the background service are out of step. Use Repair in Settings." |
| `canceled`, `timeout` (failed) | "The request was cancelled." / "grantd took too long to answer." |
| `internal` (failed) | "grantd had an internal error. Details are in the log." + "Open Logs Folder" |
| unknown reason | by category: denied "grantd said no.", refused "grantd refused this.", bad_request "grantd rejected this request.", not_found "Not found.", failed "grantd could not finish this." |
| `notRunning` (local) | see 2.5 |

**Untrusted text.** Any string that did not originate from the user's own keystrokes in this window (secret names, URLs, notes, tags, callers, cwd, argv, grant fields, error messages, stderr) is rendered through `Text(verbatim:)` after the sanitiser in 4.4. Never `Text("\(x)")` (that parses Markdown and makes links).

**Caller.** Every request the app sends carries `"caller":"grantd-app"`. For `grants add`, `caller` is `grantd-app` and `grant_caller` is the label the grant is for.

**Environment variable preview.** Wherever a secret name is shown in an editor, a gray line "Programs see this as `$NAME`" shows the derived variable: last path segment, uppercased, `.` and `-` turned into `_` (README "grantd run"). It says "unless another secret ends in the same word; then the full name is used" in a help popover.

### 3.1 Menu-bar item and popover

**Purpose.** Glanceable state and the three most common jumps.

**Menu-bar icon** (template SF Symbol, `lock.shield`): plain when healthy; with a dot badge when something needs attention (daemon down, no vault, tampered grants). Tooltip carries the headline.

**Popover** (`.window` style, 320 pt wide), top to bottom:

1. **Status header**: colored dot + headline + one detail line. Derived in this order (first match wins):
   - unreachable: see 2.5 (red) with its action button;
   - `status.proto_v != 1`: orange, "This app and the background service are out of step." + **Repair**;
   - `status.version` differs from `<helper> --version` (checked once per launch): orange, "grantd was updated. Restart the background service to finish." + **Restart** (`service install`);
   - `vault_initialized == false`: orange, "No vault yet" + **Set Up…** (opens onboarding at the vault step);
   - `tampered_grants > 0`: orange, "{n} grant(s) failed verification" + **Review** (opens Grants);
   - `keystore_tier == "dialog"`: yellow, "Vault key is protected by Keychain only" (detail: "Weaker than the Secure Enclave. See Settings.");
   - otherwise green, "grantd is running", detail "{secrets} secrets · {active_grants} active grants".
2. **Secrets quick list**: the 6 most recently updated names (from `list`), each with tier badge; click opens the Secrets window with that row selected. Footer buttons: "Add Secret…" (opens the add sheet), "All Secrets…".
3. **Recent activity**: the last 3 logical events (from `audit list` with `limit` 12, collapsed by the pairing rules in 3.4); click opens Activity. Empty: "Nothing yet. When an agent asks to use a secret, it shows up here."
4. **Footer**: "Grants ({n})…", "Activity…", "Settings…", "Quit grantd". The quit item's help text: "Quits this app. The background service keeps running."

**Protocol ops:** `status`, `list`, `audit` `list`. **Empty/error:** every section degrades independently; if `list` fails with `vault_not_initialized` the lists are hidden, not shown as errors.

### 3.2 Secrets window

**Purpose.** The only place values go in.

**Layout.** Table (Name, Protection, Expires, Tags, Updated) with `searchable` (client-side substring over name, tags, URL; case-insensitive), toolbar: Add (`+`), Import .env…, Delete (`-`), Edit. Row detail pane on the right: metadata, derived `$NAME`, expiry state ("Expired", "Expires in 3 days" - badge orange under 7 days, red when expired), URL (plain text; "Open" button only for `http`/`https` URLs, showing the host), notes (plain text, labelled "Notes (not encrypted)"), and a button "Check last 4 characters" which calls `masked` on demand and shows `****2b7c` or `********` (see 4.2 for why this is acceptable). Sorting: name ascending by default (the daemon sorts by name).

**Empty state.** "No secrets yet. Add one, or import a .env file." with both buttons.

**Protocol ops:** `list` (no filters; filtering is client-side, so `tag` and `expiring_within_s` are not used), `masked`, `set`, `delete`, `update` (G4).

**Add sheet.**

- **Name** (required). Validation mirrors `vault.ValidateName` (`internal/vault/name.go`): `^[A-Za-z0-9_/.-]+$`, at most 256 bytes, must not start or end with `/`, must not contain `..`, no empty segment, no `.` segment. Inline message per rule: "Use letters, numbers, _ . - and / only.", "Can't start or end with /.", "Can't contain ..", "Too long (256 characters max).". If the name already exists in the loaded list: "A secret with this name exists. Replace it?" turns the primary button into **Replace…** (confirmation below) and sets `overwrite: true`; the app still sends `overwrite: false` for a plain add so a race produces `secret_exists`, not a silent overwrite.
- **Value** (required): a `SecureField` with three helpers beside it: **Paste** (reads `NSPasteboard.general` once, on click; the system Cmd-V also works), **Show characters** (switches to a plain `TextField`, `privacySensitive`, autocorrect/spellcheck off; reverts to hidden when the app loses focus and after 30 s; secure keyboard input is not active while shown), and a counter that appears above 900 KiB ("Too large: 1 MiB maximum" at the limit; the daemon limit is 1 MiB, `maxValueBytes`). A toggle **Multi-line value (certificate, key file)** swaps the field for a monospaced `TextEditor` that is blurred while the window is not key; the SecureField cannot hold newlines. One trailing `\n` or `\r\n` is stripped (as the CLI does). If the value begins or ends with a space a non-blocking note says "This value starts/ends with a space. That is kept." An empty value disables the button (the daemon rejects it: `value must not be empty`).
- **Clipboard checkbox** "Clear the clipboard after saving" (default on, shown only after a Paste click): clears only if `NSPasteboard.general.changeCount` is unchanged since the paste.
- **Protection** (`min_tier`): picker "Vault default" (field omitted), "Dialog" (`"dialog"`), "Hardware" (`"hardware"`). "Hardware" is disabled when `status.keystore_tier != "hardware"` with the help "This vault's key is not in the Secure Enclave, so a hardware-only secret could never be released." (the daemon would store it and then refuse every use with `tier_unmet`). The app never sends `"none"`.
- **Tags**: token field; each tag `^[A-Za-z0-9_.:-]{1,64}$`, at most 32 (`validateTag`, `maxTags`); duplicates are collapsed by the daemon (sorted). Separators: Return, comma, space.
- **URL**: optional text; soft check (parses as a URL; if not http/https a non-blocking "This isn't a web address."), 2,048-character UI limit (the daemon has none).
- **Expires**: picker "Never" (omit), "In 7 days", "In 30 days", "In 90 days", "Pick a date…". Sent as an absolute RFC 3339 UTC time (`2026-11-24T22:59:59Z`); a picked date means 23:59:59 local time that day. Must be at least one minute in the future ("Choose a date in the future."); the daemon rejects non-future with `expires must be in the future`.
- **Notes**: optional multi-line, 4,096-character UI limit, caption "Notes are stored unencrypted. Don't put secrets here." (THREAT-MODEL §1).
- Buttons: **Cancel**, **Save** (disabled until valid). While saving: spinner, fields disabled. Success: sheet closes, row selected, value buffers zeroed (4.1). Errors: mapped per 3.0, sheet stays open with the value still in the field.

**Replace value / edit.** Context menu and toolbar "Edit…" opens the same sheet with metadata prefilled from `list` and the value empty. Two actions in a segmented control:

- "Edit details" (needs G4): changes tags, URL, notes, expiry via `update`; protection is shown read-only with the line "Set when the secret was created. To change it, replace the secret." Without G4 this segment is disabled with the help "Update support needs a newer grantd" and only "Replace value" exists.
- "Replace value": requires a new value, sends `set` with `overwrite: true` and **all** metadata fields from the form (an overwrite does not keep the old tags, URL, notes or expiry; `created_at` is preserved by the daemon). Confirmation, shown on Save:
  - Title: `Replace "{name}"?`
  - Body: `The current value will be overwritten. It can't be recovered.`
  - Buttons: `Replace` (destructive), `Cancel`.

**Delete.** Toolbar, context menu, Delete key. Confirmation:
- Title: `Delete "{name}"?`
- Body: `This permanently deletes the secret and its value from this Mac. Programs and agents that ask for it will get "secret not found". This can't be undone.`
- If any loaded grant lists exactly this name: second paragraph `{n} active grant(s) mention this secret. They stay in place but won't work until you add it again.`
- Buttons: `Delete` (destructive), `Cancel` (default). Multi-select deletes use the title `Delete {n} secrets?` and body `This permanently deletes {n} secrets and their values from this Mac. This can't be undone.`; they are sent as sequential `delete` requests, and a mid-way failure reports which names were deleted.

**Import .env.** Toolbar "Import .env…" or a file dropped on the window.

1. File choice: `fileImporter` (allow hidden files and any content type, since `.env` has none) or drop. The app opens the file itself with `FileHandle(forReadingFrom:)`; this is what keeps macOS folder-access prompts attributed to the app and the user's click.
2. **The app never reads the file's bytes.** It hands the open descriptor to the helper as standard input: `grantd import - --dry-run --on-conflict skip`. The Go parser (`vault.ParseDotenv`) is the only parser; values never enter the Swift process. (Per `cmd_import.go`, `FILE` may be `-`.)
3. Preview parsed from stdout lines of the form `(dry run) would be added: 3 (A, B, C)`, labels `added`, `overwritten`, `skipped (exists)`, `ignored (empty value)`, or `nothing to import`. Names cannot contain commas or spaces, so splitting is safe. A line the parser does not recognise aborts the import with "grantd printed something unexpected." (contract test in section 6; G7 replaces this with `--json`).
4. The sheet lists the groups: **New** (will be added), **Already exist** (names), **Empty** (ignored). Conflict choice, default **Skip existing**: `Skip existing` (`--on-conflict skip`), `Overwrite existing` (`overwrite`), `Stop if any exist` (`error`). Choosing Overwrite re-runs the dry run (to list exactly what would be overwritten) and, on Import, confirms:
   - Title: `Overwrite {n} existing secrets?`
   - Body: `These secrets will get the values from the file: {names, at most 10, then "and {k} more"}. The old values can't be recovered.`
   - Buttons: `Overwrite` (destructive), `Cancel`.
5. **Import** re-opens the file, runs the same command without `--dry-run`, and shows the real report ("Added 3, skipped 1. Nothing was overwritten."). The real report is the truth if the file changed between preview and import. The import is **not atomic** (README: one `set` per key): on failure the sheet says which stage failed and "Some secrets may have been imported. Review the list."
6. Parse errors (exit 1, stderr like `vault: dotenv line 7: invalid key`) are shown as "Line 7: invalid key" (the daemon's messages carry line numbers only, never content). Names are validated by the helper before anything is written.
7. Imported rows get default metadata (no tags, vault default protection). Audit caller is `cli` unless G5 is done. The `.env` file itself is left alone; the sheet ends with "Your .env file is still on disk. Consider deleting it." and a **Reveal in Finder** button. The app never deletes the user's file.

### 3.3 Grants window

**Purpose.** See what is pre-approved, revoke it, create a standing grant.

**List** (from `grants` `list`): columns Caller, Command (prefix joined by spaces), Folder (`cwd_prefix`), Secrets, Kind ("Standing" if `standing`, else "Session"), Expires (relative: "in 23 min", "in 29 d 4 h"), Uses left (`uses_remaining` or "No limit"). Sorted by soonest expiry. Badges:

- **Standing** (blue) for `standing: true`.
- **Expiring soon** (orange) under 10 minutes left.
- **Expired** (gray): the daemon omits expired grants from `list` (`handleGrants`), so this badge only appears for a row that crosses `expires_at` between two refreshes; the row disappears at the next poll. The client compares with `Date.now`.
- **Tampered** (red) for `tampered: true`: the row shows only the ID and the text "Failed verification. grantd ignores it. Remove it." Other fields of a tampered row are untrusted and are not displayed (same as `grantd grants`). Its only action is Remove.

**Actions.**

- **Revoke** (row button, context menu, Delete key): `grants` `revoke` with `grant_id`. Confirmation:
  - Title: `Revoke this grant?`
  - Body: `{caller} will have to ask you again before it can use {secrets} in {folder}. A command that is already running keeps running.`
  - Buttons: `Revoke` (destructive), `Cancel`.
- **Tampered row**: Title `Remove this grant?`, body `grantd could not verify this grant, so it is ignored and never allows anything. Removing it clears the warning.`, buttons `Remove` (destructive), `Cancel`. Same op.
- **Revoke All** (toolbar, disabled when the list is empty): `grants` `revoke_all`. Confirmation:
  - Title: `Revoke all {n} grants?`
  - Body: `Every agent will have to ask you again, including for standing grants you created on purpose. Commands already running keep running.`
  - Buttons: `Revoke All` (destructive), `Cancel`.
- **New standing grant…** (toolbar): the form below.

**Empty state.** "No active grants. When you choose "Allow for 1h" in an approval dialog, it appears here. You can also create a standing grant."

**Protocol ops:** `grants` with `action` = `list`, `revoke`, `revoke_all`, `add`.

#### New standing grant

A standing grant lets a caller run a command prefix with listed secrets in a folder, unprompted, for up to 90 days (README "Standing grants"). It is the most powerful object grantd stores, so the form is built to make the scope visible.

**Fields and validation** (mirrors `handleGrantAdd` and `validateRun` in `internal/broker`):

| Field | Control | Rule |
|---|---|---|
| Who is it for (`grant_caller`) | text with suggestions `claude-code` (default), other callers seen in the audit log | required; trimmed; at most 64 bytes; no control or non-printing characters (`labelOf`). Help: "Use the name the tool reports. For Claude Code this is `claude-code`." Explains it is a label and not proof of identity (README "Grants"). |
| Folder (`cwd`) | **Choose Folder…** (`NSOpenPanel`, directories only) plus a read-only path field | required; absolute; must exist and be a directory (the daemon resolves symlinks; the form shows the resolved path it will send, computed with `realpath(3)`, not `URL.resolvingSymlinksInPath`, which turns `/private/tmp/x` back into `/tmp/x` and so disagrees with the daemon). |
| Secrets (`secrets`) | checklist of current secrets plus a "Pattern…" field for globs like `aws/*` | at least 1, at most 256; each entry 1 to 256 bytes, name charset `[A-Za-z0-9_/.-]` plus glob characters `* ? [ ] { }` and no backslash; deeper glob syntax is validated by the daemon (`bad_request`, `malformed glob`). A glob grants matching secrets added later (README "Grants"); the form says so next to a glob. |
| Command (`argv`) | one text field, tokenised on whitespace with single/double quotes honoured; no shell expansion; tokens shown as chips | at least 1 token, no empty token, at most 4,096 tokens. Help: "`php artisan` also covers `php artisan migrate`." |
| Lasts (`ttl_s`) | presets 1 hour, 1 day, 7 days, 30 days, 90 days, plus custom (`d`/`h`/`m`) | greater than 0 and at most 90 days (7,776,000 s). A repo `.grantd.yml` may lower the ceiling (`max_standing_grant_ttl`); then the daemon answers `bad_request` with the limit in `message` and the app shows it as is. Never clamp locally. |
| Run limit (`uses`) | optional integer | blank = no limit; otherwise at least 1. |

**Soft warning (UI heuristic, not a daemon rule).** If the command is a single token among `sh bash zsh fish dash ksh env sudo python python3 node deno bun ruby perl php npx npm yarn pnpm`, the form shows a red callout "This lets {caller} run any code with these secrets" and requires ticking "I understand" before the button enables. Reason: THREAT-MODEL 4.7, "never for a shell or interpreter prefix".

**Summary line** under the form, always visible, in plain language: `{caller} will be able to run "{command} …" with {secrets} in {folder} and its subfolders for {duration}, without asking you again.` (plus ` It stops after {n} runs.` if set).

**The confirmation is the daemon's, and the app must not shortcut it.** The button is labelled **Ask Me to Confirm…**, not "Create". Clicking it sends exactly one `grants` `add` request. The daemon then validates, applies policy, shows its own "Create a standing grant?" dialog (osascript) and, after "Create standing grant", the Touch ID sheet; nothing is stored before both succeed (PROTOCOL.md `grants`, `internal/broker/standing.go`). While the request is open the sheet shows a spinner and: `Waiting for you to confirm in the grantd dialog, then Touch ID.` plus a **Cancel** button that closes the connection (the daemon then cancels the dialog). The app must not:

- show its own "Are you sure? Yes" that could be mistaken for the approval, or pre-fill, click, or script the dialog (no Accessibility, no AppleScript, no `osascript` from the app);
- retry automatically, or send a second `add` while one is pending;
- create the grant by any other path (there is none; the app has no way to write the vault).

Outcomes:

| Response | Shown |
|---|---|
| `ok` with `result` GrantInfo | Toast `Standing grant created. {caller} can run "{command}" with {secrets} in {folder} until {date, time}.` and the list refreshes. |
| `denied`/`user_denied` | `Not created. You cancelled the confirmation.` |
| `denied`/`approver_unavailable` | text from the table in 3.0 |
| `refused`/`policy_refused` | `A .grantd.yml in that folder does not allow this:` + `message` |
| `refused`/`tier_unmet`, `secret_expired`; `not_found`/`secret_not_found` | per 3.0, naming the secret from `message` |
| `bad_request` | `message` verbatim (it names the TTL ceiling and its source) |

Until G3 lands, the daemon's dialog ends with "Only continue if you just ran `grantd grants add` yourself." The sheet warns about this in one line: `The dialog says "grants add". That is the same request this app just sent.` Remove that line after G3.

### 3.4 Activity (audit) window

**Purpose.** What agents asked for, what you answered, whether the record is intact.

**Table** (from `audit` `list`, newest first, default `limit` 200, "Load more" up to the daemon maximum of 1,000; beyond that the footer says "Older entries are only in the CSV export."): columns Time, Event, Detail, Caller, Secrets, Result. Filter control: All, Runs, Denied or blocked, Changes. Search over detail, caller and secret names.

**Pairing rule.** A released run is two rows (README "Audit"): an `allowed_*` row with `reason == "released"` and no `exit_code`, then a `completed` row with the same `grant_id`, caller, cwd, argv and secrets, with `exit_code`/`duration_ms` and reason empty or one of `timeout`, `canceled`, `command not found`, `cannot execute command`, `not started: …`. There is no run ID. Algorithm (oldest to newest over the loaded rows): keep a list of open `released` rows; for each `completed` row, match the oldest open `released` row with identical (caller, cwd, argv, secrets, grant_id) and merge them into one event. Event text: `Ran "{argv}" ({secrets}) · exit {n} · {duration}`. A `released` row with no `completed` row: `Started "{argv}" - no result recorded` (the daemon stopped mid-run; THREAT-MODEL "Audit-before-spawn"), unless it is newer than 1 hour, then `Running…`. Rows at the edge of the loaded window may be unmatched because their partner is outside it; those show a neutral `…` instead of "no result recorded" (the app knows the oldest loaded id).

**Event labels** (`decision`, `reason`):

| Row | Label |
|---|---|
| `allowed_grant` + `released` | "Used a grant" |
| `allowed_once` + `released` | "Allowed once" |
| `allowed_new_grant` + `released` | "Allowed for a while (grant created)" |
| `allowed_new_grant` + `standing` | "Standing grant created" |
| `allowed_once` + `set` / `delete` / `show` / `update` | "Secret saved" / "Secret deleted" / "Secret revealed in a terminal" / "Secret details changed" (the daemon records these with `argv` `["grantd", verb, name]`; Detail shows the name) |
| `denied_user` | "You said no" |
| `refused_policy` | "Blocked by .grantd.yml" |
| `refused_tier` | "Blocked: protection level" |
| `error` | "Error" (reason text in Detail) |

**Detail pane** for a selected event: the full argv as one monospaced, selectable string (sanitised, 4.4, capped at 8 KB with "…"), cwd, secrets as requested and, when the row carries it, the concrete names they expanded to (`expanded`, an optional field being added to `AuditInfo` in the working tree; decode it as optional and ignore it if absent), grant ID, timings, audit IDs of the underlying rows.

**Verify.** Toolbar button "Verify Log" sends `audit` `verify`. Result banner:

- `ok: true`: green, `Log verified: {entries} entries, chain intact.` with the caption `This detects edits and removals in the middle of the log. It cannot detect the newest entries being deleted.`
- `ok: false`: red, `Log check failed at entry {first_bad_id}. Entries from there on can't be trusted. Someone may have edited the vault file. Export a copy now.` with an **Export CSV…** button. (The response itself is `ok: true`; the app reads `result.ok`.)
- request failure: normal error mapping. The banner persists until the next verify or until the window closes.

**Export CSV.** Toolbar button, `audit` `export`, then a save panel (`fileExporter` with `.commaSeparatedText`, default name `grantd-audit-{yyyy-MM-dd}.csv`, directory Documents). The CSV is written exactly as received (columns per `internal/audit/audit.go` `ExportCSV`: `id, ts, caller, cwd, argv, secrets, expanded, decision, grant_id, reason, exit_code, duration_ms`; note `expanded` is not in the README's list). If the daemon answers `failed`/`internal` ("too large to export"), the app says `The log is over 1 MB and can't be exported in one piece yet. Use Load more and copy what you need.` The panel message reads `Cells contain text chosen by other programs. Open this file in a text editor if you are not sure.` (the app does not rewrite cells, so a caller label starting with `=` would be a formula in a spreadsheet).

**Empty state.** `No activity yet.` **Protocol ops:** `audit` `list`, `verify`, `export`.

### 3.5 Settings

A `Window("Settings")` scene with four tabs. Everything here that changes the system asks first.

**General**
- **Start grantd when I log in** (toggle): `SMAppService.mainApp.register()` / `unregister()`. Reflects `SMAppService.mainApp.status`; if `.requiresApproval` it shows "Allow grantd in System Settings > General > Login Items" and a button that opens that pane (`SMAppService.openSystemSettingsLoginItems()`).
- **Keep grantd running in the background** (toggle, the "install at login" of the daemon): on = `service install`, off = confirm then `service uninstall`. Confirmation:
  - Title: `Stop the background service?`
  - Body: `Agents will not be able to use grantd until you turn it back on. Your secrets and grants stay as they are.`
  - Buttons: `Stop Service` (destructive), `Cancel`.
  Shows the `service status` fields: running (pid), plist path, exe path, and a warning row when `ExeMissing`.
- **Where grantd looks for commands** (PATH, 2.5) with Re-detect and Apply.
- **Show recent activity in the menu** (toggle).

**Connect** (also the onboarding step)
- Heading `Connect Claude Code`. A segmented control **All my projects** (default) / **Only one project**.
- Command box (monospaced, selectable) and a **Copy** button. Exact text, with `{HELPER}` = the absolute helper path, shell-quoted with single quotes if it contains anything outside `[A-Za-z0-9_./-]` (an embedded `'` becomes `'\''`):

  - All projects: `claude mcp add --scope user grantd -- {HELPER} mcp`
  - One project (run inside that project's folder): `claude mcp add grantd -- {HELPER} mcp`

  For the default install location: `claude mcp add --scope user grantd -- /Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd mcp`. The `claude mcp add [options] <name> <commandOrUrl> [args...]` syntax and `-s, --scope <scope>` (local, user, project) were checked against `claude mcp add --help` (Claude Code 2.1.310).
- `.mcp.json` box with **Copy**, pretty-printed JSON with the path JSON-escaped:

  ```json
  {
    "mcpServers": {
      "grantd": {
        "command": "/Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd",
        "args": ["mcp"]
      }
    }
  }
  ```
  Caption: `Put this in a file named .mcp.json in your project's folder. It contains a path on your Mac, so don't commit it to a shared repository.` There is deliberately no password or environment variable in it (README "Quick start" step 5).
- If an older registration may exist (the old `Contents/MacOS/grantd` path, i.e. the live install): a callout `Already connected with an older path? Run claude mcp remove grantd first, then the command above.` with its own Copy.
- **Test prompt** with Copy: `Use grantd's secret_list tool and tell me the names of my secrets.` Caption: `Claude will see names only, never values. To see an approval, ask it to run a command with a secret.`
- A link-less sentence: `Claude Code must be restarted, or run /mcp, to pick up the new server.` (the README says `/mcp` should list four tools: `secret_list`, `secret_exists`, `secret_masked`, `secret_run`; the panel names them).

**Security & data**
- Read-only facts: Version (`status.version`, protocol `proto_v`), vault protection ("Secure Enclave (hardware)" or "Keychain only (weaker)" from `keystore_tier`), approval method ("Touch ID or your password", from `approver_tier == "hardware"`), socket path, vault folder path (`~/Library/Application Support/grantd`), logs folder.
- Buttons: **Open Logs Folder** (`NSWorkspace.shared.open` on `~/Library/Logs/grantd`, which `service install` creates), **Open Vault Folder in Finder** (reveal only).
- A fixed paragraph (not editable): `Saving, replacing and deleting secrets does not ask for Touch ID, and neither does revoking a grant. Any program running as you can do those things. Touch ID protects using a secret, not managing the list. See THREAT-MODEL.md.` This is the honest statement of the gap recorded in BACKLOG.md and THREAT-MODEL 4.1 ("Set, overwrite and delete").

**Uninstall** (also in the app menu as "Uninstall grantd…")
- Sheet with checkboxes, nothing destructive pre-ticked except stopping the service:
  - [x] `Stop and remove the background service` (`service uninstall`)
  - [ ] `Delete my vault: {n} secrets, {m} grants and the audit log`
  - [ ] `Delete logs`
  - [ ] `Delete the Keychain item used by weaker protection` (shown only if `keystore_tier == "dialog"` is known; runs the helper's `keystore delete --fallback --yes`)
  - [ ] `Delete the hardware key` (shown only if `keystore_tier == "hardware"` is known; runs `keystore delete --hardware --yes`)
  - The app never calls `security delete-generic-password`: the fallback key lives in the data-protection keychain, which `security` cannot reach (it answers exit 44, "not found", for an item that is there), and the Secure Enclave key is invisible to it. Only the signed helper can delete either. The key options are shown only when the tier is known from a `status` answer; with no answer the sheet says so and offers neither.
- If "Delete my vault" or either key option is ticked, an extra paragraph and a confirmation field appear:
  - Warning for the vault: `Deleting the vault permanently removes all secrets, grants and the audit log. grantd does not keep a copy and this can't be undone.`
  - Warning for a key: `Deleting the key makes the vault permanently unreadable, even if you keep the vault file.`
  - Field: `Type "delete" to confirm.` The button stays disabled until the field equals `delete`. A key can never be deleted without the typed word, with or without the vault.
- Buttons: `Remove` (destructive), `Cancel`.
- Order of operations: `service uninstall`; wait for the socket to disappear (up to 5 s); only then remove `vault.db`, `vault.db-wal`, `vault.db-shm` and a leftover `grantd.sock` in the vault folder, then the folder if empty, then the logs, then the keys. The vault and the keys are never deleted while the daemon may hold them open, so ticking a key also stops the service. The app never passes `--force` to `keystore delete`. "The daemon has stopped" means one thing: a `status` call failed with `notRunning` (socket absent or connection refused). A timeout, a reset connection or any other failure proves nothing, so the flow stops there with `Could not tell whether grantd has stopped (…), so nothing was deleted.` and deletes nothing; a daemon error response counts as an answer (still running). If the vault's tier is not known (the last `status` failed, for instance because the daemon is down), the sheet does not guess `hardware`: it shows neither key option and says so, and if the vault is deleted anyway the result says the vault's key may still be in the Keychain.
- `keystore delete` result codes: 0 deleted; 3 no such key (the result sheet says `Keychain item was not found, so nothing was deleted` or the same for the hardware key, as a neutral line and not as a success); 2 the daemon is still running (`grantd is still running, so the … was not deleted.`); anything else shows `The … could not be deleted.` plus the helper's stderr, sanitised. The file operations use the default vault folder only (neither the Finder app nor the launchd job sees `GRANTD_HOME`/`XDG_DATA_HOME`).
- Result sheet states what remains: `The hardware key in your Keychain stays. It can't be exported and is useless without the vault file. To remove it, tick "Delete the hardware key" when you uninstall.` (only when the vault was deleted and the key was not). Then: `To disconnect Claude Code, run: claude mcp remove grantd` (Copy) and `To finish, drag grantd to the Trash.` with a **Reveal in Finder** button. The app does not delete itself.

### 3.6 Onboarding

Shown on first launch, and again from the popover's "Set Up…". State-derived, not flag-derived: each step displays as done when its condition already holds, so the owner's existing install skips straight to Connect. A `onboardingDone` flag in `UserDefaults` only controls whether the window opens by itself on launch.

| Step | Shows | Done when | Action |
|---|---|---|---|
| 1 Welcome | Three plain sentences: `Agents like Claude Code can use your passwords and API keys without ever seeing them.` / `Each time one asks, you see the exact command and approve with Touch ID.` / `Your secrets stay on this Mac, encrypted.` Where-from check (2.5): if not in Applications, the move button replaces Continue. | app is in `/Applications` or `~/Applications` | Continue |
| 2 Background service | `grantd needs a small background service so agents can reach it. macOS may tell you a background item was added; that is this.` | `status` answers | **Install Service** (`service install`, PATH computed as in 2.5) |
| 3 Vault | `Your vault is where secrets are kept. Its key lives in this Mac's Secure Enclave and can't be copied off. You'll use Touch ID when an agent asks to use a secret. Saving a secret here doesn't need it.` | `status.vault_initialized` | **Create Vault** (`<helper> init`, 30 s). Success line from stdout: `vault created at … (keystore tier: hardware)`; show "Protection: Secure Enclave". Failure with "Secure Enclave" in stderr: show `This Mac can't create a hardware key (for example inside a virtual machine).` and a secondary button **Use weaker protection…** with confirmation: Title `Use weaker protection?`, Body `The vault key will be kept in your Keychain instead of the Secure Enclave. Programs running as you could read it. Touch ID still protects every use of a secret.`, Buttons `Use Keychain`, `Cancel`; it runs `init --keychain-fallback`. Other failures: stderr in a disclosure. |
| 4 First secret | `Add your first secret, or import a .env file.` | `status.secrets > 0` | Add Secret…, Import .env…, **Skip** |
| 5 Connect | the Connect panel (3.5), with `Done` | user presses Done | sets `onboardingDone` |

Each step has Back, and no step is blocked by a later one. Closing the window mid-way is fine; the popover headline carries what is left.

## 4. Security rules for the app

### 4.1 Secret values

- A value exists in the app only inside the add/replace sheet's field (`SecureField`, or the TextField/TextEditor behind the two toggles) and in one transient request buffer.
- The request line for `set` is built by hand into a `[UInt8]` buffer (a small JSON string escaper for the value; the rest through `JSONEncoder`), written to the socket, then the buffer is overwritten with zeros and released, whether the call succeeded or failed. `Request` conforms to `CustomStringConvertible`/`CustomDebugStringConvertible` and prints `[REDACTED]` for the value, like `proto.Request.String()`.
- **Honest limit:** `SecureField` binds a Swift `String`, which cannot be wiped, and AppKit's field editor keeps its own copy. The rule is therefore: clear the binding the moment the request is built; keep no copy in any model, `@AppStorage`, `@SceneStorage`, `UserDefaults`, or restorable state; call `undoManager?.removeAllActions()` when the sheet closes; mark windows non-restorable; never put a value in a log, error string, accessibility label, or crash breadcrumb. The release build is Hardened Runtime without `get-task-allow`, so other processes cannot attach to read memory.
- No secret value is written to disk by the app, ever. The `.env` bytes go from the user's file descriptor to the helper (3.2) and never into the Swift process.
- NSPasteboard: read only on an explicit Paste click or the user's own Cmd-V. The app writes to the pasteboard only (a) the Connect panel's non-secret texts and (b) never a secret. The optional "clear after saving" only clears, and only if the change count is unchanged. The add sheet carries the footnote `If you use a clipboard manager, it may keep a copy of what you paste.`
- Logging uses `os.Logger`; dynamic strings are `.private`; request and response bodies are never logged, only op, category, reason.

### 4.2 No reveal, and why `masked` is fine

The app MUST NOT implement a "reveal", "copy value" or "show value" action in v0.2, and must never send `show`. Reasons:

1. `show` is TTY-gated by design: the rule "the value is only printed to a terminal" is enforced by the CLI (`cmd/grantd/cmd_show.go`), not the daemon, which cannot know what the client's stdout is (PROTOCOL.md `show`; THREAT-MODEL 4.1 "Using `show`"). The app cannot prove TTY-equivalent presence either: a GUI process that sends `show` and renders the answer is exactly the "client that is not a terminal" the rule exists to keep out, and a bug or a prompt-injected UI automation would turn it into a value-export button.
2. The daemon's own dialog for `show` is titled as running `grantd show NAME` and offers "Reveal once"; an app-driven request would put a dialog on screen that misdescribes who is asking.
3. A visible value in a GUI is readable by screen recorders, screenshots and accessibility clients, none of which the TTY rule exposes it to.

`masked` stays: it returns at most the last four characters of values of 12 or more characters (`********` otherwise), needs no approval, and is already offered to every agent as `secret_masked` (README MCP table). The Secrets detail pane shows it only after a click, as an identity check ("is this the key I think it is"). Anyone who wants the full value uses `grantd show NAME` in a terminal.

### 4.3 Caller string and trust

`caller` is `grantd-app` on every request (valid under `labelOf`: at most 64 bytes, printable). It is informational and unauthenticated, as for every client; the daemon does not and cannot treat it as proof of the app's identity in v0.2. Consequences the UI must not paper over: an agent can send the same string; the audit rows the app causes (`set`, `delete`, `update`) say `grantd-app` only as a label.

### 4.4 Untrusted text from the daemon

Untrusted fields: `caller`, `cwd`, `argv`, `secrets`, `reason`, `message`, grant fields, secret `url`/`notes`/`tags`, helper stderr. The daemon bounds `caller` (64 bytes, no control characters) but the audit `argv`/`cwd` can be 4,096 elements of anything, and `url`/`notes` are free text.

Sanitiser (`GrantdKit.DisplayText.sanitise`), applied before any display, copy or export of a display string (not to the CSV bytes):

1. Replace C0 and C1 control characters (except `\n` in the multi-line detail pane, `\t` shown as a visible arrow) with `⟦U+XXXX⟧`.
2. Replace bidirectional and invisible formatting characters with the same visible escape: U+061C, U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF.
3. Truncate in the middle to 200 characters in table cells and 8,192 in the detail pane, with `…`.
4. Render with `Text(verbatim:)` or an `NSTextField` configured with `allowsEditingTextAttributes = false`, `isSelectable = true`, data detectors off. No Markdown, no link detection, no attributed text built from these strings.
5. `url` is opened only on an explicit click, only if `URL(string:)` parses with scheme `http` or `https` and a non-empty host; the host is displayed next to the button. Never auto-open, never `file:`/`x-apple.*`/custom schemes.
6. A path from the daemon (`cwd`, `cwd_prefix`) is only displayed; "Reveal in Finder" is offered only after checking it with `FileManager` and not following a symlink out of what the user sees.

### 4.5 Sandbox and Hardened Runtime

**App Sandbox: off for v0.2.** Reasons:

- The socket lives in `~/Library/Application Support/grantd/`, outside any container; a sandboxed app cannot connect to it without a temporary-exception entitlement, and such exceptions are what the sandbox exists to avoid.
- The app spawns the helper for `init`, `import` and `service`; a sandboxed parent's children inherit the sandbox, which would break `launchctl bootstrap`, writing `~/Library/LaunchAgents/dev.grantd.daemon.plist`, and the Keychain access group.
- The helper bundle is not a sandboxed helper; sandboxing only the outer app would still stop it from launching it with the needed environment.

Since the app is not sandboxed, its safety comes from what it does not do (4.6).

**Hardened Runtime: on (`--options runtime`), both bundles, with no exception entitlements.** Compatible, and required, settings:

| Entitlement or flag | Setting | Why |
|---|---|---|
| `com.apple.security.app-sandbox` | absent | above |
| `com.apple.security.cs.allow-jit`, `allow-unsigned-executable-memory` | absent | SwiftUI app and the Go helper need neither (the live Go bundle already runs with `flags=runtime`) |
| `com.apple.security.cs.disable-library-validation` | absent | no third-party frameworks (a later Sparkle would still load under library validation if signed by the same team) |
| `com.apple.security.cs.allow-dyld-environment-variables` | absent | blocks `DYLD_INSERT_LIBRARIES` injection |
| `com.apple.security.get-task-allow` | Debug builds only | Release must not carry it (memory of the app holds a value for a moment) |
| `com.apple.security.automation.apple-events` | absent | the app must not script other apps (4.6) |
| `com.apple.application-identifier`, `keychain-access-groups` | present on the helper; present on the app too in v0.2 (one entitlements file) | only the helper uses them |

Info.plist keys for the app: `LSUIElement` true, `LSMultipleInstancesProhibited` true, `LSMinimumSystemVersion` 14.0, `CFBundleExecutable` `grantd-app`. No `NSAppleEventsUsageDescription`, no `NSAppTransportSecurity` exceptions (the app opens no network connection).

### 4.6 The app must not

- send `show`, `run`, or any op not listed in section 6(a);
- read or write the vault file (except the uninstall flow's deletion after the service is stopped), read the Keychain, or call Security.framework key APIs (the only Security.framework calls are the code-signature reads of 4.8, which touch no key);
- display, log, copy or persist a value;
- click, drive or dismiss the daemon's dialogs, or request Accessibility, Automation or Screen Recording permission;
- approve anything on the user's behalf, or create/modify a grant except through `grants` `add` with the daemon's confirmation;
- read `~/.claude.json` or any other tool's configuration;
- make network requests;
- run the helper's `daemon` or `mcp` verbs.

### 4.7 Future work (v0.3, not designed here): approval moves into the app

Goal: replace the osascript chooser with a native alert/sheet. Why it needs more than UI work: today the daemon is the only party that decides, and every decision input is a system UI answered by the user (`internal/approve/darwin/doc.go`). If the daemon accepts an "approved" answer over the socket, then every same-UID process becomes a potential approver, and the peer-UID check (THREAT-MODEL 4.6) identifies the user, not the program. So the daemon must be able to say "this answer came from the genuine grantd app".

Reasoning the v0.3 design has to follow:

- **Verify the peer's code, not its PID.** Read the peer's audit token from the socket (`getsockopt` `LOCAL_PEERTOKEN`) and use `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit`, then `SecCodeCheckValidity` against a designated requirement pinning identifier and team (for example `identifier "dev.grantd.app" and anchor apple generic and certificate leaf[subject.OU] = "MT2QHQX6PS"`). A PID is reusable and racy; an audit token names one process instance.
- **The app must be hard to inject into**, otherwise the check proves nothing: Hardened Runtime on, library validation on, no `get-task-allow`, no `allow-dyld-environment-variables`, which is why section 4.5 insists on them now.
- **Keep Touch ID in the daemon.** Move only the chooser (once / for N / deny); the daemon still runs `LAContext` itself after an allow, so the app is trusted for "which button" and not for "the user authenticated". An app-side authentication result sent over the socket would make the app's signature the entire boundary.
- **Bind the answer to the request.** The daemon sends the full request (caller, cwd, argv, expanded secrets, scope) to the verified app for display and accepts an answer only on that connection, once, with a nonce, so the app cannot be tricked into approving a different request than the one shown.
- **Accessibility scripting of an in-app dialog is the same residual risk as of an osascript dialog** (THREAT-MODEL 4.4), which is why the authentication sheet keeps following the button.
- A signed-requirement check also changes what `caller` can mean: the daemon could mark requests from the verified app as such, instead of trusting the label.

None of this is built in v0.2. The only v0.2 consequence is the hardening in 4.5.

### 4.8 Who is on the other end of the socket

The socket sits in `~/Library/Application Support/grantd`, a folder the user owns. Any program running as the user can bind that path when the daemon is stopped (or move the real socket aside and bind its own), and the app would then send it whatever a request contains. For most requests that is no worse than what such a program can already read. A **typed secret value** is different, so the app checks who answers before it sends one.

- **Which requests.** Every request that carries a plaintext value: `set` (the add and replace sheet), `update` if it ever carries a value (today it never does), and `.env` import. Read-only requests (`status`, `list`, `masked`, `grants list`, `audit list`, ...) and requests without a value (`delete`, `grants add`) are not checked, so polling does not pay for it.
- **How.** After `connect` and before the first byte is written, the app reads the peer's pid from the connected socket (`getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)`), asks for its code object (`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributePid`) and runs `SecCodeCheckValidity` against `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`. `<TEAMID>` is the team identifier in the app's own signature, read at run time (`SecCodeCopySelf`, `SecCodeCopySigningInformation`), so a re-signed build needs no change. The string is built only from a ten-character upper-case alphanumeric team identifier (`PeerVerifier.requirement(teamID:)`), nothing else reaches the requirement language. The daemon is the helper inside the app bundle, signed with the same team, so this accepts it and refuses an unrelated program.
- **Import.** The values of an import travel from the user's file to the helper process, which opens its own connection, so the app cannot check that connection. A real import (not the dry run, which sends nothing) first connects once, checks the peer the same way, closes and only then starts the helper. This is a pre-flight and not a guarantee: a program could swap the socket between the check and the helper's connect.
- **On a mismatch** (or if the pid, the code object or the requirement cannot be obtained: it fails closed) the request is not written and the user sees `The process answering grantd's socket is not grantd. Nothing was sent.` (`GrantdError.peerNotGrantd`). The value buffer is wiped as on every other path.
- **When it is skipped.** If the running app has no team identifier (an unsigned or ad-hoc development build, the unit tests), the check is skipped without a message. It is also off in development mode (`GRANTD_SOCKET` set), where the app talks to the unsigned dev daemon by design and shows the "Development socket" banner. In a signed release build the check always runs.
- **Limits, stated.** The pid is not an audit token: a process could hand the connected descriptor to another or a pid could be reused between the check and the write. `LOCAL_PEERTOKEN` with `kSecGuestAttributeAudit` closes that and is the better primitive (section 4.7 uses it for the daemon's side). Same-team code is trusted: another app signed by the same team passes. This protects against an unrelated program on the socket path, not against the owner's own other builds.

## 5. Build and signing

### 5.1 Xcode project, with the logic in a Swift package

**Decision: an Xcode project checked in at `app/Grantd.xcodeproj` for the app target, and a local Swift package `app/GrantdKit` for everything that is not UI.** `make app` drives `xcodebuild`.

Why Xcode and not a SwiftPM-only executable: the app needs an asset catalog and icon, a String Catalog, an Info.plist with launch-services keys, a run-script phase that embeds the helper bundle, and entitlements; SwiftPM can produce an executable but not a `.app` with these, so it would need a pile of custom scripts that Xcode already provides. Why the package: `swift test --package-path app/GrantdKit` builds and runs the protocol client and its tests with no signing identity, no provisioning profile and no Xcode GUI, which is what an implementing agent and CI need. `xcodegen` is installed on this machine (`/opt/homebrew/bin/xcodegen`) and may be used once to generate the initial `.xcodeproj`; after that the checked-in project is the source and there is no `project.yml` (two sources of truth drift).

```
app/
  Grantd.xcodeproj/
  Grantd/                  SwiftUI sources, Info.plist, Assets.xcassets, Localizable.xcstrings
  GrantdKit/               Package.swift, Sources/GrantdKit/, Tests/GrantdKitTests/
build/bundle/
  helper-Info.plist        was Info.plist; CFBundleExecutable grantd, LSBackgroundOnly, no LSUIElement
  grantd-app.entitlements  unchanged; used for both bundles
```

Ignore in git: `/build/xcode`, `/build/grantd-dev`, `app/**/xcuserdata`, `app/GrantdKit/.build`.

### 5.2 Targets

The names below are what the implementer adds to the Makefile (existing `build`, `bundle`, `sign-bundle` stay valid names). Do not break `make ci`; app targets are not part of it until a macOS runner with Xcode exists.

| Target | Does |
|---|---|
| `make helper` | `CGO_ENABLED=1 CGO_CFLAGS=-mmacosx-version-min=14.0 CGO_LDFLAGS=-mmacosx-version-min=14.0 go build -ldflags '-X main.version=$(VERSION)' -o bin/grantd ./cmd/grantd`. Then asserts `otool -l bin/grantd` reports `minos 14.0`. |
| `make app` | depends on `helper`. `xcodebuild -project app/Grantd.xcodeproj -scheme Grantd -configuration Release -derivedDataPath build/xcode CODE_SIGNING_ALLOWED=NO MACOSX_DEPLOYMENT_TARGET=14.0 MARKETING_VERSION=… CURRENT_PROJECT_VERSION=$(BUILD_NUMBER) build`, then copies the product to `dist/grantd.app` (replacing it). Unsigned. |
| `make sign-bundle` | same variables as today (`IDENTITY`, `PROFILE`, `TEAM_ID`, `BUNDLE_ID`, `KEYCHAIN_GROUP`), new recipe in 5.3. |
| `make app-test` | builds the dev daemon (`go build -tags grantd_dev -o build/grantd-dev ./cmd/grantd`), then `GRANTD_DEV_BIN=$(PWD)/build/grantd-dev swift test --package-path app/GrantdKit`. |
| `make app-dev-daemon` | runs the dev daemon on `/tmp/gd-dev/s.sock` with `GRANTD_HOME=/tmp/gd-dev` and `GRANTD_DEV_APPROVE=allow` for UI work (5.5). |

**Embedding the Go helper.** `make helper` runs first; the Xcode target has a Run Script build phase "Embed grantd helper", after "Copy Bundle Resources", that creates `$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers/grantd-daemon.app/Contents/{Info.plist,MacOS/grantd}` from `$SRCROOT/../bin/grantd` and `$SRCROOT/../build/bundle/helper-Info.plist` (same `@BUNDLE_ID@`/`@VERSION@`/`@BUILD@`/`@MIN_MACOS@` substitution as the current `bundle` recipe, with `@BUNDLE_ID@` = `dev.grantd.app.daemon` and `@MIN_MACOS@` = `14.0`, then `plutil -lint`). It fails the build with "bin/grantd missing: run make helper" if the binary is absent. It declares the two inputs and the output so Xcode can skip it. The target sets `ENABLE_USER_SCRIPT_SANDBOXING = NO` (the default in current Xcode is YES, which would stop the script reading `../bin`). The Xcode target itself does no code signing; there is one signing path (5.3).

### 5.3 The one signing path

`make sign-bundle` (existing guards for `IDENTITY`, `PROFILE`, `TEAM_ID` stay) does, in this order:

```sh
cp "$PROFILE" dist/grantd.app/Contents/embedded.provisionprofile
cp "$PROFILE" dist/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/embedded.provisionprofile
# expand build/bundle/grantd-app.entitlements into dist/grantd-app.entitlements, as the current recipe does
codesign --force --options runtime --timestamp --sign "$IDENTITY" \
  --entitlements dist/grantd-app.entitlements dist/grantd.app/Contents/Helpers/grantd-daemon.app
codesign --force --options runtime --timestamp --sign "$IDENTITY" \
  --entitlements dist/grantd-app.entitlements dist/grantd.app
codesign --verify --deep --strict --verbose=2 dist/grantd.app
codesign -d --entitlements - dist/grantd.app
codesign -d --entitlements - dist/grantd.app/Contents/Helpers/grantd-daemon.app
```

Inner first, outer second, no `--deep` on the signing calls (the outer seal records the already-signed inner bundle). I ran the same sequence (without `--timestamp`) on a scratch bundle with this Mac's Apple Development identity: `codesign --verify --deep --strict` passed and both executables launched. The recipe ends by printing the smoke test the old recipe printed, pointed at the helper: `GRANTD_HOME=$(mktemp -d) …/grantd-daemon.app/Contents/MacOS/grantd init     # must print: keystore tier: hardware`. The profile must cover `keychain-access-groups` for `TEAMID.dev.grantd` (the existing check in MANUAL-TEST-MACOS §2c(b) applies unchanged), and the same file serves both bundles.

### 5.4 Minimum macOS 14, and what was checked

Floor: **macOS 14.0**. It is the lowest release with `SettingsLink`/`OpenSettingsAction` (14.0) and `@Observable`; `MenuBarExtra` (13.0) and `SMAppService.mainApp` (13.0) are older. Checked on this machine (Xcode 27.1, `xcrun --show-sdk-path` = `…/MacOSX.platform/Developer/SDKs/MacOSX.sdk`, SDK 27.0), by reading `SwiftUI.framework/…/arm64e-apple-macos.swiftinterface` and `ServiceManagement.framework/Headers/SMAppService.h`:

- `struct MenuBarExtra<Label, Content>`: `@available(macOS 13.0, *)`; initialisers with and without `isInserted:`.
- `WindowMenuBarExtraStyle` and `MenuBarExtraStyle` exist (`.menuBarExtraStyle(.window)`).
- `struct SettingsLink<Label>`: `@available(macOS 14.0, *)`; `OpenSettingsAction`/`openSettings` `@available(macOS 14.0, *)`.
- `SecureField`, `fileImporter`, `fileExporter`, `confirmationDialog`, `Table`, `searchable`, `dropDestination`, `windowResizability` are present.
- `SMAppService.mainApp`, `register`, `unregister`, `status`, `SMAppServiceStatusRequiresApproval`, `+openSystemSettingsLoginItems` are present, all `macos(13.0)`.
- A scratch file using `MenuBarExtra` with `.menuBarExtraStyle(.window)`, `SettingsLink`, `SecureField`, `fileExporter`, `Settings`, `Window`, `@Observable` and `SMAppService.mainApp.register()` **type-checks with `swiftc -typecheck -parse-as-library -target arm64-apple-macos14.0`** against that SDK.

Not checked: behaviour on a real macOS 14, 15 or 26 machine (only macOS 27.0.1 is available here); the deployment target is enforced by the compiler's availability checking, not by running on those releases (Appendix A).

The Go helper must be built for 14.0 explicitly (G2): the default build records `minos 27.0` (verified with `otool -l bin/grantd`), and `make bundle` copies that into `LSMinimumSystemVersion`. With the two `-mmacosx-version-min=14.0` flags the same source produced `minos 14.0` (verified).

### 5.5 Developing the UI without a signing identity

An unsigned or ad-hoc app cannot run the real helper (the restricted entitlements fail), and does not need to: set `GRANTD_SOCKET=/tmp/gd-dev/s.sock` in the Xcode scheme and run `make app-dev-daemon`. The app then talks to the insecure dev daemon (`grantd_dev`: constant public key, tier `none`, approver auto-allows with `GRANTD_DEV_APPROVE=allow`; README "Environment"; never use real secrets with it) and is in development mode (2.3), so it cannot touch the real launchd job or vault. The dev daemon's approver tier is `none`, so the UI states that depend on `hardware` are exercised with canned `status` fixtures in tests.

## 6. Testing

UI tests (XCUITest) are optional and not required for v0.2. Required: (a) and (b).

### 6(a). Swift unit tests for the protocol client, against the Go dev daemon

Target: `GrantdKitTests` in `app/GrantdKit`. Fixture `DevDaemon` (XCTest `setUp`/`tearDown`):

1. `GRANTD_DEV_BIN` points at `build/grantd-dev` (built by `make app-test`; unset from the Xcode GUI means `XCTSkip`, never a silent pass in `make`).
2. Create `/tmp/gdt-<random>` (short: the socket path limit is 103 bytes on macOS and `NSTemporaryDirectory()` can exceed it).
3. Run `grantd-dev init` with `GRANTD_HOME=<dir>`, then `grantd-dev daemon --socket <dir>/s.sock` with `GRANTD_HOME=<dir>` and `GRANTD_DEV_APPROVE` set per test class (`allow`, `allow-no-standing`, or unset which auto-denies). Wait for the socket (5 s), then run the test, then SIGTERM and delete the directory. A variant starts the daemon **before** `init` to test the no-vault state.

The tests must exercise **every op the app uses** and the behaviours the UI depends on:

| Area | Cases |
|---|---|
| `status` | before `init`: `vault_initialized` false and every other op fails `failed`/`vault_not_initialized`; after: fields decode (`version`, `proto_v` 1, `pid`, `started_at`, tiers `none`, `secrets`, `active_grants`, `socket` equals the fixture path); `tampered_grants` absent decodes to 0 |
| `set` | minimal; with all metadata (tags, url, notes, `expires`, `min_tier: "dialog"`) and read back through `list`; tags de-duplicated and sorted; second `set` without `overwrite` fails `bad_request`/`secret_exists`; with `overwrite` succeeds, `created_at` preserved, old metadata replaced; empty value, past `expires`, bad `min_tier` fail `bad_request`; 1 MiB value succeeds, 1 MiB + 1 fails; a value whose JSON line exceeds 4 MiB is rejected locally before connecting |
| `list` | sorted by name; no value anywhere in the raw response; metadata round trip; unknown extra fields ignored (canned JSON) |
| `masked` | value of 12+ characters gives `****` + last four; shorter gives `********`; missing name gives `not_found`/`secret_not_found` |
| `delete` | ok, then second call `not_found`/`secret_not_found` |
| `update` (if G4) | each field; `clear_expires`; absent name `not_found`; no value or tier change possible; audit row reason `update` |
| `grants` `list` | empty; after `add` |
| `grants` `add` | with `allow`: result `GrantInfo` has `standing: true`, the TTL, `cmd_prefix`, `secrets`, `cwd_prefix` equal to the symlink-resolved folder, `uses_remaining` when `uses` set; `ttl_s` above 90 days gives `bad_request` with the ceiling in `message`; unknown secret gives `not_found`/`secret_not_found`; missing `grant_caller` gives `bad_request`; non-existent `cwd` gives `bad_request`; with approver unset gives `denied`/`user_denied`; with `allow-no-standing` the same |
| `grants` `revoke` | ok; unknown ID `not_found`/`grant_not_found`; `revoke_all` leaves an empty list |
| `grants` tampered | canned JSON with `tampered: true` decodes (a tampered row cannot be created through the protocol) |
| `audit` `list` | rows for the app's own `set`/`delete` (`decision` `allowed_once`, `reason` `set`/`delete`, `caller` `grantd-app`, `argv` `["grantd","set",<name>]`); `limit` honoured; newest first |
| `audit` `verify` | `ok: true` with `entries` equal to the row count; then corrupt a row in the fixture's `vault.db` with `sqlite3` (drop the trigger, edit a row) and expect `ok: false` with `first_bad_id` |
| `audit` `export` | `csv` parses as RFC 4180; header is exactly `id,ts,caller,cwd,argv,secrets,expanded,decision,grant_id,reason,exit_code,duration_ms`; row count equals `list`; `argv` cell is a JSON array |
| Pairing | a test-only `run` request (not exposed by the app; the dev approver allows it) creates a `released` + `completed` pair; the pairing function merges them; canned rows cover interleaved runs by the same caller, a lone `released`, a lone `completed`, and rows cut at the window edge |
| Validator parity | for ~40 names, `validateSecretName(n) == nil` exactly when the daemon's `exists` accepts `n` (invalid names give `bad_request`); same for ~20 tags through `set` |
| Transport | daemon not running gives `notRunning`; a `Client` used twice throws; a fake server that closes without a response gives `noResponse`; stream frames before the final response are skipped; cancelling a pending call closes the connection (a fake server observes EOF); no `shutdown(SHUT_WR)` is ever issued (fake server asserts the write side stays open) |
| Hygiene | `String(describing:)`, `debugDescription` and `dump` of a `Request` with a value contain `[REDACTED]` and not the value; the request buffer is all zero after `send` (test hook); sanitiser cases (RLO U+202E, NUL, ESC sequences, 5,000-character arg, zero-width joiner); MCP snippet cases (path with spaces, with `'`, with `"` and a backslash; JSON round-trips; shell quoting parses back with `/bin/sh -c 'printf %s\n' …`) |
| Helpers | `import` report parser against real `grantd-dev import - --dry-run` output for each conflict mode (a contract test that fails loudly if the CLI wording changes); `service status` parser against canned outputs of each state |

### 6(b). Manual checklist to append to MANUAL-TEST-MACOS.md (new section "8. v0.2 app")

The implementing agent appends these (in the file's existing style, with expected outcomes) when the screens exist:

1. `make helper`: `otool -l bin/grantd` shows `minos 14.0`.
2. `make app && make sign-bundle …`: `codesign --verify --deep --strict` passes; `codesign -d --entitlements -` of the app and of `Contents/Helpers/grantd-daemon.app` shows `TEAMID.dev.grantd.app` and `TEAMID.dev.grantd`; `LSMinimumSystemVersion` is `14.0`; neither shows `get-task-allow` nor `app-sandbox`.
3. Helper alone: `GRANTD_HOME=$(mktemp -d) …/grantd-daemon.app/Contents/MacOS/grantd init` prints `keystore tier: hardware`.
4. Negative control (documents the layout finding): a copy of the Go binary at `Contents/Helpers/grantd` signed the same way exits 137 and the log says `No matching profile found`.
5. Fresh install: drag to `/Applications`, open; onboarding completes; the "background item added" notification (if any) is noted; `launchctl print gui/$(id -u)/dev.grantd.daemon` names the helper path.
6. Upgrade over the live pre-v0.2 install: popover shows Repair; Repair fixes it; the vault opens, secrets and grants are intact; `claude mcp` registration with the old path is reported by the Connect panel.
7. Run from `~/Downloads` or a mounted DMG: service and vault actions are blocked with "Move grantd to your Applications folder first"; the move-and-relaunch button works.
8. Quit the app: the daemon keeps running and a Claude Code `secret_run` still prompts.
9. `launchctl kill SIGTERM gui/$(id -u)/dev.grantd.daemon`: popover turns red (3 s open, 30 s closed) and recovers; repeated kills show "grantd keeps stopping".
10. Add a secret with the SecureField, with Paste, with Show characters (hides on focus loss and after 30 s) and with the multi-line toggle (PEM). Afterwards `grep -r <sentinel>` over `~/Library/Logs/grantd`, `~/Library/Preferences`, `~/Library/Saved Application State`, and the app's temp dirs finds nothing; `grantd list` shows metadata only.
11. Replace and Delete show the exact confirmation texts of 3.2; Cancel changes nothing.
12. Import: dry-run preview, Skip, Overwrite (confirmation text), a file with a bad line (shows "Line N: …"), an empty value; the `.env` file is untouched; no value in any log.
13. "Hardware" protection is disabled on a Keychain-fallback vault.
14. Edit details (only if G4): tags, URL, notes, expiry change; value and protection do not.
15. Grants: an "Allow for 1h" from a real agent run appears within 5 s; Revoke and Revoke All show the exact texts; the next agent run prompts again.
16. Standing grant: the daemon's dialog and Touch ID both appear; Cancel at the dialog, Cancel at Touch ID, and Esc each give "Not created."; approving shows the toast; the next agent run needs no prompt; the app never shows an approve button of its own.
17. Standing grant with 91 days shows the daemon's ceiling message; a lone `bash`/`sh` prefix requires the extra tick.
18. Tampered grant: edit a `grants` row with `sqlite3`; the row turns red with only its ID; Remove works.
19. Activity: an agent run shows as one event with exit code; `kill -9` the daemon mid-run shows "no result recorded"; Verify Log passes; after editing an audit row with `sqlite3` it fails with `first_bad_id`; Export CSV opens in a text editor with 12 columns.
20. Hostile text: an agent run with `argv` containing U+202E, ESC sequences and a 5,000-character argument is displayed escaped and truncated, with no layout break, no link, no Markdown.
21. Settings: turn the background service off and on; Start-at-login (log out and in: icon appears); PATH field: an agent running `php --version` or another Homebrew tool works after install from a Finder-launched app.
22. Connect: both Copy buttons put exactly the displayed text on the clipboard; running the command in a new terminal registers the server; `/mcp` in Claude Code lists `secret_list`, `secret_exists`, `secret_masked`, `secret_run`; repeat with the app in a folder whose name contains a space and an apostrophe.
23. Uninstall: each checkbox separately; vault deletion needs the typed word; afterwards the plist, vault files and logs are gone as selected; the app is still there; the dialog states the hardware key remains unless "Delete the hardware key" was ticked; a key box alone needs the typed word; "not found" is reported as not deleted.
24. Privacy: System Settings > Privacy & Security shows no Accessibility, Automation or Screen Recording request from grantd; `lsof -a -p <app pid> -i` shows no network sockets.

## 7. Work breakdown

Ordered; each step is one commit (or two) and has a definition of done (DoD). Steps 1 to 2 are Go and build; 3 to 4 are the client and shell; 5 to 11 are screens in order of user value; then onboarding, settings, uninstall, docs. `G*` are the changes in 2.8.

| # | Step | DoD |
|---|---|---|
| 1 | **G1**: `bundleExe` finds `Contents/Helpers/grantd-daemon.app/Contents/MacOS/<CFBundleExecutable>`; legacy bundles unchanged. Tests in `internal/service/bundle_test.go`. | `go test ./internal/service` passes with new cases: helper bundle resolves; legacy `MacOS/grantd` bundle resolves; a helper whose executable name escapes the bundle is rejected; `make ci` green. |
| 2 | **G2 + bundle restructure + skeleton app**: `app/` with a menu-bar-only SwiftUI skeleton (empty `MenuBarExtra`), `build/bundle/helper-Info.plist`, Run Script embedding, `make helper`, `make app`, new `make sign-bundle` recipe (5.2, 5.3). Rebase on the other agent's Makefile edits first. | On the owner's Mac: `make app && make sign-bundle IDENTITY=… PROFILE=… TEAM_ID=MT2QHQX6PS` verifies; manual items 1 to 3 pass; the skeleton shows a menu-bar icon; `<helper> service install --exe <helper path>` installs a daemon that answers `grantd status`; `minos 14.0`. |
| 3 | **GrantdKit client**: `Client`, models, `DaemonError`, socket resolver, request builder with zeroed buffer, `DevDaemon` fixture, `make app-test`, tests for `status`, `set`, `list`, `masked`, `delete`, transport and hygiene rows of 6(a). | `make app-test` green; no test skips under `make`; coverage of the listed rows. |
| 4 | **Shell + Monitor**: `Monitor` (status/service polling per 2.4), helper runner (2.6), PATH detection, popover status header and the down-state actions Start/Repair/Restart (2.5), location check, development mode, activation-policy handling. No data screens. | Manual items 5 (partly), 7, 8, 9; unit tests for the state derivation using canned `status`/`service status` fixtures. |
| 5 | **Secrets window**: list, search, detail with `masked`, Add sheet with all fields and validators, Replace, Delete, empty state. | Validator parity test green; manual items 10, 11, 13; no value in logs/prefs. |
| 6 | **Grants window**: list, badges, Revoke, Revoke All, Remove for tampered; popover grant count. | `grants` tests green; manual items 15 and 18. |
| 7 | **Activity window**: list, pairing, labels, detail, filters, Verify, Export. | Pairing and `audit` tests green; manual items 19 and 20. |
| 8 | **Import .env** via descriptor to the helper, preview, conflict modes, confirmation, report. Optional **G5**. | Contract test on the real dev output green; manual item 12. |
| 9 | **Standing grant form** and **G3** (dialog sentence; update `reason_test.go`, README, THREAT-MODEL 4.7 in the same commit). Remove the interim warning line in 3.3 once G3 is in. | `grants add` tests green; `go test ./internal/approve/...` green; manual items 16 and 17. |
| 10 | **Edit details** with **G4** (`update` op in `internal/proto`, `internal/broker`, `internal/vault`, PROTOCOL.md, tests, THREAT-MODEL note). If the owner declines G4, ship only "Replace value" and drop this step. | `update` tests green on both sides; manual item 14. |
| 11 | **Connect panel** (3.5): both scopes, `.mcp.json`, old-path callout, test prompt, snippet builder with tests. | Snippet tests green; manual item 22. |
| 12 | **Onboarding** (3.6): five steps, state-derived, vault creation via helper, weaker-protection retry. | Fresh-user run from manual item 5; the live install skips to Connect. |
| 13 | **Settings** (3.5): General (login item, background service toggle, PATH), Security & data. | Manual item 21. |
| 14 | **Uninstall** flow. | Manual item 23. |
| 15 | **Docs**: append 6(b) to MANUAL-TEST-MACOS.md as section 8; update README Install ("Signed bundle", `--exe` paths) and BACKLOG (roadmap 4 and the deferred items this spec adds: G6, G7, v0.3 approval, `keystore` key removal). | A reader can follow README to a working install with the app; checklist present. |

## 8. Open questions for the owner

Each has a default so work can start now.

1. **How does a non-developer get the app?** The current Apple Development profile is limited to registered devices and expires (the live profile expires 2027-10-25), so the "vibe coder" cannot run this build. Default: v0.2 is built and signed for the owner's own Macs with the existing Apple Development path; a Developer ID + notarisation + DMG pipeline is a separate follow-up (v0.2.1) that reuses the same `IDENTITY`/`PROFILE` variables, and the nested-helper layout must be re-verified with a Developer ID profile then.
2. **Add the `update` op (G4) so tags, URL, notes and expiry can be edited without retyping the value?** It lets any socket client, an agent included, change or clear an expiry without knowing the value (it can already replace the value). Default: yes; ship "Replace value" first and "Edit details" when the op lands.
3. **Change the standing-grant dialog sentence (G3) to "Only continue if you just asked for this yourself."?** It touches the daemon's wording and its tests, README and THREAT-MODEL 4.7. Default: yes, in step 9.
4. **Should the app itself start at login, in addition to the background service?** Without it the menu-bar icon is gone after a restart, though agents keep working. Default: yes, on by default at the end of onboarding, with the toggle in Settings.
5. **Which scope does the Connect panel show first for `claude mcp add`?** `--scope user` (every project) is what a non-terminal user wants, but it registers grantd in all projects. Default: `--scope user` first; "Only one project" as the second option and the `.mcp.json` snippet with the warning about committing a machine-specific path.
6. **Uninstall and the Secure Enclave key** (invisible to `security`; only the signed bundle's binary can delete it). Resolved: the helper has `grantd keystore delete --fallback|--hardware --yes` and Uninstall offers both options behind the typed word (3.5). The app does not pass `--force`.

## Appendix A. Not verified

- **The nested-helper layout with a Developer ID profile**, and with the app on any machine other than this one. The tests used this Mac's Apple Development identity and the profile embedded in the live bundle (App ID `MT2QHQX6PS.dev.grantd.app`; entitlement `keychain-access-groups` `MT2QHQX6PS.dev.grantd`). A second bundle identifier (`dev.grantd.app.daemon`) under the same profile worked; whether a profile restricted to one explicit App ID keeps allowing it on a Developer ID profile was not tried.
- **Launch through launchd** from the nested helper. I ran the helper directly (`exec` from a shell) and ran `init` against a throwaway `GRANTD_HOME` (which uses the existing Secure Enclave key in the shared group; the live vault was not touched, `grantd status` against the live daemon was unchanged). The AMFI path is the same for a launchd-started process, but `service install --exe <helper>` end to end is step 2's DoD.
- **macOS 14 to 26 behaviour.** Only macOS 27.0.1 and SDK 27.0 exist here. Availability was checked in the SDK interfaces and by type-checking against `-target arm64-apple-macos14.0`; nothing was run on those releases. The Go helper at `minos 14.0` was built but not run on a 14 machine.
- **The "Background Items Added" notification** for a LaunchAgent written by an app, and whether `SMAppService.mainApp.register()` prompts for approval on a fresh account: documented system behaviour as I understand it, not observed.
- **Folder-access (TCC) prompts** for `.env` files under Desktop/Documents when the app opens the file and passes the descriptor to the helper: the design avoids the child process opening the file by path, but I did not exercise it.
- **Exact `claude mcp add` behaviour of `--scope user`** beyond `claude mcp add --help` (2.1.310): not executed (it would modify the owner's Claude configuration).
- **Daemon log growth** is inferred from the code (INFO line per request in `internal/daemon/daemon.go`, no rotation found by grep), and from the live `daemon.err.log`, which shows `op=status` lines; I did not measure a day of polling.
- **SecureField internals.** That AppKit keeps its own copy of the typed string is the usual behaviour of text fields; not inspected here.
- **`SwiftUI.Table` behaviour at 1,000 audit rows, `searchable` placement in a `Window` scene**: standard APIs, no performance measurements.

## Appendix B. What was checked on this machine

- Layout experiment (section 2.1): scratch copy of `~/Applications/grantd.app`, `codesign --force --options runtime --sign <Apple Development: Jetmir Mehmetaj (W5Q6SQZZNG)> --entitlements dist/grantd-app.entitlements`; `Contents/MacOS/grantd` and `Contents/Helpers/grantd` beside a trivial main executable: exit 137, `log show` lines from `amfid` (`Code=-413 "No matching profile found"`) and the kernel (`Code has restricted entitlements, but the validation of its code signature failed`); nested `Helpers/*.app` with a copied profile: `--version` runs, `init` prints `keystore tier: hardware`, `codesign --verify --deep --strict` passes. The live bundle's `CodeResources` has `nested` rules for `Helpers/` and `MacOS/`.
- Live bundle: `codesign -dvv` (Identifier `dev.grantd.app`, TeamIdentifier `MT2QHQX6PS`, `flags=0x10000(runtime)`), entitlements as in 2.1, profile expiry 2027-10-25.
- Go: `go version go1.27.3`; `otool -l` minos 27.0 (default) and 14.0 (with `CGO_CFLAGS`/`CGO_LDFLAGS` `-mmacosx-version-min=14.0`).
- SDK and Swift: Xcode 27.1, Swift 6.4, SDK 27.0; availability of `MenuBarExtra`, `SettingsLink`, `OpenSettingsAction`, `SMAppService`; type-check at macOS 14.0.
- `claude mcp add --help` (Claude Code 2.1.310): `claude mcp add [options] <name> <commandOrUrl> [args...]`, `-s, --scope <scope>` with `local` (default), `user`, `project`; `--` separates the server command.
- Code read for every protocol, validation and exit-code claim: `internal/proto`, `internal/broker` (`secrets.go`, `admin.go`, `standing.go`, `run.go`), `internal/vault` (`name.go`, `secrets.go`, `dotenv.go`, `import.go`), `internal/audit/audit.go`, `internal/approve/darwin` (`chooser.go`, `reason.go`, `doc.go`), `internal/service`, `internal/mcp`, `internal/daemon`, `cmd/grantd` (`cmd_*.go`, `clihelp.go`).
