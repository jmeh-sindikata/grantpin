# macOS manual test checklist (HANDOFF §11 step 7)

The Secure Enclave keystore (`internal/keystore/darwin`) and the Touch ID
approver (`internal/approve/darwin`) need real hardware and a logged-in GUI
session, so CI cannot exercise them. Everything that touches the Keychain or
shows a prompt is behind `GRANTD_MANUAL_TEST=1`. A plain `go test ./...` never
prompts and never touches the Keychain.

Run this on a Mac with Touch ID, in a normal Terminal/iTerm window in a
logged-in desktop session (not over SSH, not inside tmux started from SSH).

## 0. Expectations in one paragraph

- The **keystore** never prompts (the SE key has no user-presence flag by
  design; presence is the Approver's job). If it prompts, that is a bug.
- The **approver** shows the `osascript` dialog, then (only after an Allow
  button) exactly one Touch ID / password prompt per `Ask`.
- The manual tests use throwaway keys named `dev.grantd.test.<random>` and
  delete them afterwards. They never touch the real vault key
  (`dev.grantd.vault-kek`).

## 1. Build with cgo

```sh
export PATH=/opt/homebrew/bin:$PATH
cd /path/to/Secrets
go env CGO_ENABLED          # must print 1
xcode-select -p             # Xcode or Command Line Tools must be installed
go build ./...
go vet ./internal/keystore/darwin ./internal/approve/darwin
go test -race ./internal/keystore/darwin ./internal/approve/darwin   # pure Go, no prompts
```

## 2. Keystore manual tests

```sh
GRANTD_MANUAL_TEST=1 go test -race -count=1 -v ./internal/keystore/darwin -run 'TestManual(SecureEnclave|Fallback)'
```

**No prompt should appear.**

| Test | What it proves |
|---|---|
| `TestManualSecureEnclaveRoundTrip` | creates an SE key, wraps and unwraps a 32-byte key, a second store finds the existing key, a flipped bit makes unwrap fail |
| `TestManualFallbackRoundTrip` | forces the Keychain fallback path (random KEK in a generic-password item), round-trip and tamper check |

### 2a. Decision tree: does the Secure Enclave work from this binary?

A permanent Secure Enclave key lives in the data-protection keychain, which
macOS opens only to code that carries a keychain access group. A plain
`go test` / `go build` binary is unsigned (the Go linker only adds a bare
ad-hoc signature) and usually fails with `OSStatus -34018`
(`errSecMissingEntitlement`). Work through these steps in order and stop at the
first one that passes.

**Step 1: run unsigned.** Section 2's command as written.
- Passes (`mode secure-enclave`, no errors): done. Report outcome **A**.
- Fails with `-34018` (or `-4` / `-25291`): go to step 2.
- Fails with anything else: copy the exact error text, report outcome **E**.

**Step 2: sign ad-hoc with the entitlements plist and retry.**

```sh
make sign                      # ad-hoc signs bin/grantd (does not run it)
# the keystore tests run inside the test binary, so sign that one too:
T=$(mktemp -d)
go test -c -o "$T/keystore.test" ./internal/keystore/darwin
codesign --force --sign - --identifier dev.grantd.grantd \
  --entitlements build/grantd.entitlements "$T/keystore.test"
GRANTD_MANUAL_TEST=1 "$T/keystore.test" -test.v -test.count=1 \
  -test.run 'TestManual(SecureEnclave|Fallback)'
```

- Passes: report outcome **B**.
- Process is killed immediately (`Killed: 9`, exit 137): the entitlement was
  rejected at launch; report outcome **C**.
- Still `-34018`: go to step 3 (report outcome **D** if you stop here).

What the plist contains and what is and is not known (macOS 27, Apple silicon):
- `build/grantd.entitlements` holds only `com.apple.application-identifier =
  dev.grantd.grantd`. **Verified:** a binary ad-hoc signed with this entitlement
  launches normally.
- `keychain-access-groups` is deliberately left out. **Verified:** an ad-hoc
  binary carrying it is SIGKILLed at launch (exit 137), because it is a
  restricted entitlement that needs a provisioning profile.
- **Not verified:** whether the keychain daemon accepts
  `com.apple.application-identifier` on an ad-hoc binary with no team ID as an
  access group for data-protection-keychain and Secure Enclave items. I could
  not test it without touching the Keychain. It may well still return -34018;
  that is exactly what this step finds out. If it does, the likely real fix is
  a proper Apple Development / Developer ID identity plus a provisioning
  profile (which needs an app-bundle style package), and we should decide
  whether that is in scope for v0.1.

**Step 3: use the Keychain fallback and accept the tier consequence.**

```sh
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/keystore/darwin -run TestManualFallbackRoundTrip
```

- Passes: report outcome **F**.
- Daemon-side, this is `keystoredarwin.New(keystoredarwin.WithAllowKeychainFallback(true))`.
- Tier consequence: the keystore then reports `TierDialog`, not `TierHardware`.
  Secrets with `min_tier = hardware` (the macOS default) are **refused**, not
  downgraded, unless their min tier is lowered to `dialog` on purpose. The KEK
  is readable by anything running as you with login-keychain access, so
  protection is only your login session plus the Approver prompt.

**What to report back** (so we can decide on tiers): the outcome letter and the
exact `OSStatus` line from the failing run.

| Outcome | Meaning | Tier decision it drives |
|---|---|---|
| A | works unsigned | `TierHardware` as designed |
| B | works after `make sign` | `TierHardware`, `make sign` becomes part of install |
| C | signed binary killed at launch | signing as tried is a dead end |
| D | signed, still -34018 | need real identity + profile, or fallback |
| E | some other error (paste it) | investigate |
| F | only the fallback works | `TierDialog` on this Mac |

**Recorded result (2026-10-25, macOS 27.0.1, Apple silicon): outcome D.**
- Unsigned `go test` binary: Secure Enclave key creation fails with
  `OSStatus -34018` (`errSecMissingEntitlement`).
- After `make sign` (ad-hoc, entitlement
  `com.apple.application-identifier=dev.grantd.grantd`) the binary launches, but
  `find Secure Enclave key: A required entitlement is not present. (OSStatus -34018)`.
- The Keychain fallback round-trip (`TestManualFallbackRoundTrip`) passes.

Conclusion: ad-hoc signing with an application identifier is **not** accepted as
a keychain access group. The Secure Enclave needs a real Apple Development or
Developer ID identity with a provisioning profile, i.e. an app bundle, planned
for v0.2 (BACKLOG.md roadmap step 4). Until then `grantd init --keychain-fallback`
is the working path for a from-source build. The signed-bundle route that
restores the Secure Enclave is in 2c.

### 2b. Verify the key exists

- Fallback item (login keychain): `security find-generic-password -s dev.grantd -a vault-kek`
  (add `-g` to print the secret to the terminal; do not do that on a screen
  you share). Keychain Access.app shows it under "login" -> Passwords.
- Secure Enclave key and any item in the **data-protection keychain**: these are
  deliberately invisible to the `security` CLI and Keychain Access. The
  evidence they exist is that `New()` reports `Mode() == "secure-enclave"` and
  Unwrap of an old blob still works from a new process (section 2 does this).

### 2c. Signed bundle (Developer ID)

Goal: run the daemon from a signed `.app` bundle whose provisioning profile
carries `keychain-access-groups`, so the Secure Enclave key can be created
(`keystore tier: hardware`). It needs an Apple Developer account (an Apple
Development identity and profile work for your own Macs). Nothing in `make ci`
or the unit tests uses this; it is a manual test on your Mac. It needs Xcode:
`make bundle` runs `xcodebuild` for the menu-bar app (`make ci-app` is the
non-signing check of that part).

Layout produced by `make bundle` (v0.2; see [UI-SPEC.md](UI-SPEC.md) section 2.1):

```
dist/grantd.app/Contents/
  Info.plist                 from app/Grantd/Info.plist; id dev.grantd.app; CFBundleExecutable grantd-app (the SwiftUI app)
  MacOS/grantd-app           the menu-bar app (popover, Secrets, Grants, Activity, Welcome and Settings)
  embedded.provisionprofile  added by make sign-bundle
  Helpers/grantd-daemon.app/
    Contents/
      Info.plist             from build/bundle/helper-Info.plist; id dev.grantd.app.daemon; CFBundleExecutable grantd
      MacOS/grantd           the Go binary (daemon, CLI, MCP shim), built for macOS 14.0
      embedded.provisionprofile   a copy of the same profile, added by make sign-bundle
```

**Why the Go binary is in a bundle of its own.** A Go binary signed with the
restricted `keychain-access-groups` entitlement and placed at
`Contents/MacOS/grantd` or `Contents/Helpers/grantd` next to a different main
executable is killed at launch (exit 137, `amfid`: `No matching profile found`):
the provisioning profile is only looked up for a bundle's main executable. Inside
its own nested `.app` with a copy of the profile it launches, and `grantd init`
prints `keystore tier: hardware`. Both bundles are signed with the same identity
and entitlements, inside out (helper first), without `--deep`.

**Minimum macOS.** `make helper` builds `bin/grantd` with
`CGO_CFLAGS`/`CGO_LDFLAGS` `-mmacosx-version-min=14.0` and fails unless
`otool -l bin/grantd` shows `minos 14.0` (without the flags the binary records the
build machine's macOS, 27.0 here, and would not start on older releases). Both
Info.plists pin `LSMinimumSystemVersion` 14.0 (`MIN_MACOS` in the Makefile).
Check the bundled binary:

```sh
otool -l dist/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd | grep -A3 LC_BUILD_VERSION   # minos 14.0
```

**Version.** `make build` and `make bundle` print the version they use and where it came from. Order: `make VERSION=x` on the command line, then `git describe --tags --always --dirty`, then the contents of a `VERSION` file in the repo root, then `dev`. A tree from plain `git archive` has no `.git` and would report `dev`; run `make dist-src` in the checkout instead, which writes `dist/grantd-src.tar.gz` containing a `VERSION` file with the hash, so building from the unpacked archive (`make bundle`) carries it.

The bundle identifier lives in one place, `BUNDLE_ID` in the Makefile
(`dev.grantd.app`; override with `make BUNDLE_ID=...`), and `KEYCHAIN_GROUP`
(`dev.grantd`) is the keychain group without the team prefix. Rename the project
there and in the portal.

**What is verified and what is not.** Verified on this repo's machine (macOS
27.0.1, Xcode 27.1): `make bundle` produces the layout above with valid
`Info.plist` files and `minos 14.0` on the Go binary; `make sign-bundle` refuses
to run without `IDENTITY`, `PROFILE` and `TEAM_ID`; with an **Apple Development**
identity and its macOS App Development profile (App ID `TEAMID.dev.grantd.app`,
keychain group `TEAMID.dev.grantd`), `make bundle && make sign-bundle ...` signs
both bundles, `codesign --verify --deep --strict dist/grantd.app` passes, and
`GRANTD_HOME=$(mktemp -d) .../grantd-daemon.app/Contents/MacOS/grantd init`
prints `keystore tier: hardware`. `codesign` embeds an entitlements file verbatim
(it does **not** expand `$(TeamIdentifierPrefix)`, an Xcode build setting), which
is why `make sign-bundle` expands it into `dist/grantd-app.entitlements` first.
Not run: a **Developer ID** identity and profile, notarisation, and the nested
layout on any other Mac. The portal steps below are written from memory of the
portal and marked "verify" where the exact wording or option may differ.

#### (a) App ID with Keychain Sharing

1. In the developer portal (developer.apple.com, Account, Certificates,
   Identifiers & Profiles) open **Identifiers** and add a new **App ID** of type
   App with an **explicit** Bundle ID `dev.grantd.app` (same as `BUNDLE_ID`).
2. Under Capabilities enable **Keychain Sharing** and save. (Verify the
   capability is offered for a macOS App ID and whether the portal asks you to
   name groups; in Xcode the group names are listed in the target, the portal
   usually only records the capability.)
3. What matters is what ends up in the **profile**: it must carry a
   `keychain-access-groups` entitlement that covers `TEAMID.dev.grantd`, either
   exactly or as the wildcard `TEAMID.*`. The capability is how you get that
   entitlement into the profile; step (b) shows how to check it.
4. You also need a **Developer ID Application** certificate (Certificates, add,
   Developer ID Application; verify whether your role may create it, it is
   usually restricted to the Account Holder) installed in your login keychain.
   `security find-identity -v -p codesigning` should list `Developer ID
   Application: Your Name (TEAMID)`. The ten characters in parentheses are your
   Team ID (also under Membership details in the portal).

#### (b) Provisioning profile

1. Profiles, add, and choose the **Developer ID** distribution type for macOS
   (verify the exact label; it is the profile type for apps distributed outside
   the Mac App Store). Pick the App ID `dev.grantd.app`, then the Developer ID
   Application certificate, name it, and download the `.provisionprofile`.
2. Inspect it before using it (this only decodes the file):

   ```sh
   security cms -D -i ~/Downloads/grantd.provisionprofile | plutil -p -
   ```

   Look under `Entitlements` for `keychain-access-groups` and
   `com.apple.application-identifier` (`TEAMID.dev.grantd.app`), and check that
   `TeamIdentifier` is your Team ID and that your certificate is in
   `DeveloperCertificates`. If `keychain-access-groups` lists only
   `TEAMID.dev.grantd.app` (the app's own group) and not `TEAMID.*` or
   `TEAMID.dev.grantd`, sign with `KEYCHAIN_GROUP=dev.grantd.app` instead; the
   entitlements must stay inside what the profile allows or the process is
   killed at launch (exit 137, the same as the ad-hoc `keychain-access-groups`
   result in 2a).

#### (c) Build and sign

```sh
export PATH=/opt/homebrew/bin:$PATH
make bundle
make sign-bundle IDENTITY="Developer ID Application: Your Name (TEAMID)" \
  PROFILE=~/Downloads/grantd.provisionprofile TEAM_ID=TEAMID
```

`sign-bundle` copies the profile to `Contents/embedded.provisionprofile` and to
the helper's `Contents/embedded.provisionprofile`, expands
`build/bundle/grantd-app.entitlements` with your Team ID, runs
`codesign --force --options runtime --timestamp --sign ... --entitlements ...`
on the helper bundle and then on the outer app (inside out, no `--deep`), then
`codesign --verify --deep --strict` and prints the entitlements of both.
`--timestamp` contacts Apple's timestamp server, so you need network access
(`make sign-bundle CODESIGN_TIMESTAMP=--timestamp=none` skips it). Signing may ask for access to the certificate's private key in
your keychain: that is your own prompt, allow it. It prints `signed and
verified: dist/grantd.app` on success. Re-run `make bundle` before signing again
(it starts from a clean `dist/grantd.app`).

#### (d) Check the entitlements

```sh
codesign -d --entitlements - dist/grantd.app
codesign -d --entitlements - dist/grantd.app/Contents/Helpers/grantd-daemon.app
codesign -dvv dist/grantd.app 2>&1 | grep -E 'Identifier|Authority|TeamIdentifier|flags'
codesign -dvv dist/grantd.app/Contents/Helpers/grantd-daemon.app 2>&1 | grep -E 'Identifier|Authority|TeamIdentifier|flags'
```

Both bundles should show the entitlements below.

Expected (macOS 27 prints the tree form; older releases print XML):

```
[Key] com.apple.application-identifier
[Value]
    [String] TEAMID.dev.grantd.app
[Key] keychain-access-groups
[Value]
    [Array]
        [String] TEAMID.dev.grantd
```

and `Identifier=dev.grantd.app` (the helper: `dev.grantd.app.daemon`), an `Authority=Developer ID Application: ...`
line, `TeamIdentifier=TEAMID`, and `flags=0x10000(runtime)`. A literal
`$(TeamIdentifierPrefix)` anywhere means the unexpanded template got signed.

#### (e) Does the Secure Enclave work now?

The keystore manual test (`GRANTD_MANUAL_TEST=1 go test ...`) does **not**
exercise the bundle: the test binary is a different executable outside the
bundle with no profile, so it stays at outcome D. The check is the bundled
Go binary (the helper's, not the SwiftUI app's), on a fresh vault:

```sh
GRANTD_HOME=$(mktemp -d) dist/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd init
```

Expected: `vault created at ... (keystore tier: hardware)`, no prompt. This
creates the real Secure Enclave key (tag `dev.grantd.vault-kek`) in the
data-protection keychain, which is shared by every vault of your user; it stays
after the throwaway vault is deleted. It is invisible to `security` and
Keychain Access, and the production-key removal test (2d) cannot see it either
(that test binary is not in the bundle); there is no remove command yet.

Failure modes:
- `OSStatus -34018` (`errSecMissingEntitlement`): the keychain still does not
  accept the access group. Re-check (b); if the profile and entitlements agree
  and it persists, `codesign -d --entitlements -` output and the exact error are
  the report (a possible next step is also signing with
  `com.apple.developer.team-identifier`, which Xcode normally adds; not tried).
- Killed at launch (exit 137, `Killed: 9`): an entitlement is not covered by the
  profile; Console.app (or `log show`) around the launch time usually names the
  rejected entitlement (not verified).
- A Gatekeeper "cannot be opened" dialog: this applies to bundles that arrive
  with the quarantine flag (downloaded or copied from another Mac). A bundle you
  built locally does not have it. Distributing to other Macs needs notarisation
  (`xcrun notarytool`), which is not set up here.

#### (f) Run the daemon from the bundle

```sh
H=dist/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd
$H service install --exe "$PWD/$H"
# or, after cp -R dist/grantd.app /Applications/ :
$H service install --exe /Applications/grantd.app
$H service status          # exe: .../grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd
```

`--exe` takes the Go binary, the helper `grantd-daemon.app`, or the outer
`grantd.app`; the last two are resolved to
`Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd`. The launchd plist
always names that binary, because the signature and profile apply to the bundle
that contains the running file. The outer app's own executable
(`Contents/MacOS/grantd-app`, the UI) is refused: `service install` never installs
a job that runs the UI. A path under a temporary directory is still refused. Any grantd can run the
`install` command; only the binary it points at needs to be the bundled one.
Put the bundle in `/Applications` with `cp -R` (not a symlink or a move of a
build directory you will rebuild), and run `service install` again after every
rebuild and re-sign.

The CLI, the MCP shim and the auto-started daemon need no special handling, but
use the bundled binary so they all share one identity:

```sh
G=/Applications/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd
ln -sf "$G" ~/.local/bin/grantd   # optional
claude mcp add grantd -- "$G" mcp
```

`grantd mcp` starts the daemon it needs with `os.Executable()`, so launched
from the inner binary it starts the inner binary. (Whether the kernel keeps the
bundle context when started through a symlink was not tested; `grantd init`
printing `hardware` through the symlink answers it.)

#### (g) Existing vaults and migration

- A vault created earlier with `grantd init --keychain-fallback` keeps working
  with the bundled daemon: the wrapped key's blob names its own mode and is
  opened that way (see the `internal/keystore/darwin` package doc). The fallback
  item sits in the login keychain, written by an older, differently signed
  binary, so macOS may ask once whether the new binary may use it. Allow only if
  you trust the bundle you just built.
- Moving to the Secure Enclave means a **new** vault: stop the service, move
  the old `vault.db` (and any `-wal`/`-shm` files next to it) aside, run
  `grantd init` with the bundled binary, then `grantd set` each secret again.
  Keep the old vault file until you have checked the new one. There is no
  migrate command yet (BACKLOG.md).

### 2d. Remove the real vault key (destructive)

This makes any existing vault permanently unreadable.

```sh
GRANTD_MANUAL_TEST=1 GRANTD_MANUAL_REMOVE_PRODUCTION_KEY=yes \
  go test -count=1 -v ./internal/keystore/darwin -run TestManualRemoveProductionKey
```

Fallback item only, via CLI: `security delete-generic-password -s dev.grantd -a vault-kek`.

## 3. Approver manual tests

The default approver is two steps: an `osascript` dialog (Deny / Allow once /
Allow for 1h), then, for either Allow button, the Touch ID / password prompt.
Deny stops after step one.

```sh
# 3a. Dialog only, no Touch ID:
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualChooserOnly
```

Expected: a caution-icon dialog titled "grantd" reading *An agent is asking
grantd to release secrets: grantd-manual-test wants to run `echo hello` with
MANUAL_TEST_SECRET in /tmp/grantd-manual-test (no policy)*, buttons **Deny**
(default, also Esc) / **Allow once** / **Allow for 1h**. Check:

1. Click each button in three runs; the log shows `choice=0` (Deny, also for
   Esc and Return since Deny is the default), `choice=1` (once), `choice=2` (for 1h).
2. Leave it alone for 2 minutes: it closes by itself and logs `choice=0`.
3. If no dialog appears or the test errors with `choice dialog failed`, record the
   `osascript` message (an Automation / permission message would be news).

```sh
# 3b. Full chain (dialog, then Touch ID for Allow):
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualPromptsOnce
```

1. **Allow once** then touch the sensor: `decision={Allow:true TTL:0s ...}`.
2. **Allow for 1h** then touch the sensor: `Allow:true TTL:1h0m0s`. The Touch ID
   text then also says "(approval lasts 1h)".
3. **Deny**: `Allow:false Reason:user denied`, and **no Touch ID prompt appears**.
4. **Allow once**, then cancel the Touch ID sheet: deny, `user denied`.
5. **Allow once**, "Use Password...", wrong password: the sheet retries; after the
   system gives up: deny, `authentication failed`. Right password: Allow.

```sh
# 3c. LocalAuthentication alone (chooser off, WithChooser(false)):
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualLAOnly
```

Expected: one system sheet with Touch ID and a **Deny** button (the cancel
label) plus "Use Password...". LocalAuthentication frames the text as
`"<app>" is trying to <reason>`; if the wording reads badly, reword `BuildReason`
in `internal/approve/darwin/reason.go` (record it in your report).

```sh
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualCancelViaContext
```

Expected: the Touch ID sheet appears, disappears by itself after about 3
seconds and the test passes (`context.DeadlineExceeded`, never an allow).

To assert instead of eyeball in `TestManualPromptsOnce`: `GRANTD_MANUAL_EXPECT=allow` or `=deny`.

## 4. Expected behaviour on edge cases

| Situation | Expected |
|---|---|
| Deny / Esc / close the dialog, or cancel the Touch ID sheet | `Decision{Allow:false, Reason:"user denied"}`, no error |
| Nobody answers the dialog for 120s | dialog closes itself, deny |
| `osascript` cannot show the dialog | `errors.Is(err, ErrChooserFailed)`, never an allow (use `WithChooser(false)` to skip it) |
| Agent clicks the dialog via Accessibility scripting | still needs Touch ID / password afterwards (the reason LA always follows an Allow button) |
| Wrong password | sheet retries; after the system gives up: deny, reason `authentication failed` |
| Touch ID locked out (too many failures) | sheet asks for the password directly (policy is DeviceOwnerAuthentication) |
| Lid closed, clamshell with external display, or Mac without Touch ID | the password sheet is used; this still counts as TierHardware per HANDOFF §5 table |
| No device passcode/password set | `errors.Is(err, ErrUnavailable)`; never an allow |
| Daemon started (or vault first used) while the screen is locked, e.g. launchd right after login | unwrap fails with `OSStatus -25308`; the daemon stays up, `grantd status` shows `vault: locked (retrying, last error: ...)`, ops answer `failed`/`vault_locked`; after unlock the next request works with no restart; the log has one WARN and one recovery line |
| Screen locked / fast user switch mid-prompt | `errors.Is(err, ErrInterrupted)`; no decision |
| No GUI session (SSH, headless launchd) | `errors.Is(err, ErrNoGUISession)` immediately, no prompt |
| `ctx` cancelled while the prompt is up | prompt is invalidated, `ctx.Err()` returned |
| Agent shell tries to influence it (env vars, files, stdin, socket) | nothing reads those; only the system sheet decides |

## 5. Known limits to confirm or record

- **Chooser is an `osascript` dialog.** It is ordinary UI, so a process on
  this account with Accessibility permission could script it; the
  LocalAuthentication prompt that follows an Allow button is what stops that.
  `WithChooser(false)` skips the dialog (LA-only, allow-once, or the
  `WithDefaultTTL` duration). The "Allow for N" button is offered only when the
  request's `SuggestedTTL` is non-zero.
- **First-prompt app name.** The prompt shows the process that called
  LocalAuthentication (`grantd`, or `go` test binary during these tests).
- **Key access after lock.** SE key protection class is
  `WhenUnlockedThisDeviceOnly`: Unwrap fails while the Mac is locked. The
  launchd agent must unwrap after login/unlock, not at boot.
- **Login-keychain prompts (fallback only).** If the fallback KEK ends up in the
  legacy login keychain (unsigned binary, no data-protection keychain), macOS
  may show "grantd wants to use your confidential information" when a
  *rebuilt* binary reads an item created by an older build. That prompt is the
  Keychain's own ACL, not grantd's; Always Allow only for binaries you trust.
- **Tier of the SE keystore.** `Tier() == TierHardware` means the key is
  hardware-bound and non-exportable, not that Unwrap prompts (it does not).

## 6. Virtual machines / no Secure Enclave

Symptoms: `Wrap` fails with `ErrSecureEnclaveUnavailable` (OSStatus -4
`errSecUnimplemented`, -25291, or -34018). That is the safe default.

To accept a weaker keystore knowingly, construct it with the fallback:

```go
ks, err := keystoredarwin.New(keystoredarwin.WithAllowKeychainFallback(true))
```

(the CLI flag/config for this is wired by the integration step, not here). Then
`ks.(*keystoredarwin.Store).Mode()` reports `keychain-fallback` and
`Tier()` reports `dialog`, so secrets with `min_tier = hardware` are refused,
never downgraded. In fallback mode anything running as you with access to your
login keychain can read the KEK, so the vault is only as safe as your login
session. Run section 2's `TestManualFallbackRoundTrip` to validate it.

The approver on a VM usually still works (password prompt) if a GUI session and
a user password exist.

## 7. Clean up

```sh
security find-generic-password -s dev.grantd.test     # should find nothing left over
```

Test keys are deleted by `t.Cleanup`; an interrupted run may leave
`dev.grantd.test.*` items. Delete any with
`security delete-generic-password -s dev.grantd.test -a <account>`.

## 8. v0.2 app

The menu-bar app (`dist/grantd.app`, [UI-SPEC.md](UI-SPEC.md)) was compiled and
rendered offscreen against the dev daemon, never opened on a screen. This is the
first real look at it. Do items 1 to 4 with the signed bundle from 2c. For the
screens, a development session is safer for items 10 to 20: `make app-dev-daemon`
in one terminal, then start the app with `GRANTD_SOCKET=/tmp/gd-dev/s.sock` (the
app then shows "Development socket: ..." and touches neither the launchd job, the
vault, nor the login item). Items 5 to 9, 21, 23 and the Move-to-Applications
part of 7 need the real install and a spare account or a Mac you can reset.

1. `make helper`: `otool -l bin/grantd | grep -A3 LC_BUILD_VERSION` shows `minos 14.0`.
2. `make app && make sign-bundle IDENTITY=... PROFILE=... TEAM_ID=...`:
   `codesign --verify --deep --strict dist/grantd.app` passes;
   `codesign -d --entitlements - dist/grantd.app` and the same for
   `dist/grantd.app/Contents/Helpers/grantd-daemon.app` show `TEAMID.dev.grantd.app`
   and `TEAMID.dev.grantd`; `LSMinimumSystemVersion` is `14.0` in both Info.plists;
   neither shows `get-task-allow` or `app-sandbox`.
3. Helper alone: `GRANTD_HOME=$(mktemp -d) dist/grantd.app/Contents/Helpers/grantd-daemon.app/Contents/MacOS/grantd init`
   prints `keystore tier: hardware`.
4. Negative control (documents the layout finding): a copy of the Go binary at
   `Contents/Helpers/grantd`, signed the same way, exits 137 and the log says
   `No matching profile found`.
5. Fresh install: drag to `/Applications`, open. The Welcome window opens by
   itself. Steps: Welcome, Install Service, Create Vault (Touch ID is not asked),
   first secret (Add Secret... and Import .env... open the Secrets window; Skip
   works), Connect Claude Code with "Start grantd when I log in" ticked. Note
   whether macOS shows a "background item added" notification.
   `launchctl print gui/$(id -u)/dev.grantd.daemon` names the helper path. Closing
   the window half-way is fine: the popover says what is left ("No vault yet" with
   **Set Up...** opens the window at the vault step). Opening grantd again from
   Finder while it runs opens the Secrets window and does not start a second copy.
6. Upgrade over the live pre-v0.2 install: the popover says "The background
   service points to a file that no longer exists" with **Repair**; Repair fixes
   it; the vault opens, secrets and grants are intact. Settings > Connect shows
   "Already connected with an older path?" with `claude mcp remove grantd` and
   Copy; the old registration is reported there.
7. Run from `~/Downloads` or a mounted disk image: the popover and Settings say
   "Move grantd to your Applications folder first", Start, Repair, Install Service,
   Create Vault and the login toggle are off, and **Move to Applications and
   Relaunch** copies the app (it never replaces an app of the same name) and starts
   the copy.
8. Quit the app from the popover: the daemon keeps running and a Claude Code
   `secret_run` still prompts.
9. `launchctl kill SIGTERM gui/$(id -u)/dev.grantd.daemon`: the popover turns red
   (3 s open, 15 s closed) and recovers on its own. A repeated kill within a minute
   shows "grantd keeps stopping" with **Open Logs Folder**. With the service
   removed (`grantd service uninstall`) the popover says "grantd is not set up to
   run in the background" with **Start**; with the app moved away, "The background
   service points to a file that no longer exists" with **Repair**.
10. Add a secret with the SecureField, with Paste, with Show characters (hides on
    focus loss and after 30 s) and with the multi-line toggle (PEM). Afterwards
    `grep -r <sentinel>` over `~/Library/Logs/grantd`, `~/Library/Preferences`,
    `~/Library/Saved Application State` and the app's temp dirs finds nothing;
    `grantd list` shows metadata only. The popover lists the six newest secrets
    (a click opens the Secrets window with that row selected); the Secrets table
    has an Updated column.
11. Replace and Delete show the exact texts of 3.2 (`Replace "{name}"?`,
    `Delete "{name}"?`); Cancel changes nothing.
12. Import: dry-run preview, Skip, Overwrite (`Overwrite {n} existing secrets?`),
    a file with a bad line (shows "Line N: ..."), an empty value; the `.env` file is
    untouched; no value in any log.
13. "Hardware" protection is disabled on a Keychain-fallback vault.
14. Edit details: tags, URL, notes, expiry change; value and protection do not.
15. Grants: an "Allow for 1h" from a real agent run appears within 5 s, with the
    caller, command, folder, secrets and "in N min". **Revoke** (button, context
    menu or Delete key) asks `Revoke this grant?` / `{caller} will have to ask you
    again before it can use {secrets} in {folder}. A command that is already running
    keeps running.` with **Revoke** and Cancel. **Revoke All** asks `Revoke all {n}
    grants?` / `Every agent will have to ask you again, including for standing
    grants you created on purpose. Commands already running keep running.` with
    **Revoke All** and Cancel. The next agent run prompts again. The popover's
    "Grants (n)..." row opens the window.
16. Standing grant (New Standing Grant...): the form's button is **Ask Me to
    Confirm...**. Pressing it shows "Waiting for you to confirm in the grantd dialog,
    then Touch ID." and the daemon's "Create a standing grant?" dialog and Touch ID
    both appear. Cancel at the dialog, Cancel at Touch ID and Esc each give "Not
    created. You cancelled the confirmation."; **Cancel Request** while the dialog is
    open withdraws the dialog and creates nothing; approving shows the toast
    `Standing grant created. {caller} can run "{command}" with {secrets} in {folder}
    until {date, time}.`; the next agent run needs no prompt; the app never shows an
    approve button of its own. The caller field offers `claude-code` and callers seen
    in the activity log; the folder picker shows the symlink-resolved path.
17. Standing grant with a custom lifetime of 91 d is stopped in the form ("A
    standing grant lasts 90 days at most."). A `.grantd.yml` with
    `max_standing_grant_ttl: 1h` in the folder and a 7 day request shows the
    daemon's message (naming the ceiling and the file) as it is. A policy that does
    not list the command shows "A .grantd.yml in that folder does not allow this:".
    A lone `bash`, `sh` or other interpreter prefix shows the red "This lets {caller}
    run any code with these secrets" and needs "I understand".
18. Tampered grant: edit a `grants` row with `sqlite3` (or insert a row with a wrong
    MAC, see `internal/e2e` `TestForgedGrantRowDoesNotBypassThePrompt`); the popover
    shows the TAMPERED warning with **Review**, the row turns red with the
    "Tampered" badge, only its ID and "Failed verification. grantd ignores it. Remove
    it."; **Remove** asks `Remove this grant?` / `grantd could not verify this grant,
    so it is ignored and never allows anything. Removing it clears the warning.`
19. Activity: an agent run shows as one event with its exit code and duration;
    `kill -9` the daemon mid-run and restart it: the run shows "No result recorded".
    A denial shows "You said no" with a hand icon and "Denied"; a policy or tier
    refusal shows "Blocked ...". Filter (All, Runs, Denied or blocked, Changes) and
    search work. **Verify Log** shows "Log verified: {n} entries, chain intact." with
    its caption; after editing an audit row with `sqlite3` it shows "Log check failed
    at entry {id}..." with **Export CSV...**. **Export CSV...** opens a save panel
    named `grantd-audit-YYYY-MM-DD.csv` and the file opens in a text editor with 12
    columns. **Load More** appears when 200 rows are loaded and more exist, up to
    1,000; past that the footer says "Older entries are only in the CSV export.".
20. Hostile text: an agent run with `argv` containing U+202E, ESC sequences and a
    5,000-character argument is displayed escaped and truncated, with no layout
    break, no link, no Markdown, in Activity, Grants and the popover.
21. Settings: General. Turn the background service off (`Stop the background
    service?`, button **Stop Service**) and on; "Start grantd when I log in" (log out
    and in: the icon appears; if macOS asks, the text "Allow grantd in System
    Settings > General > Login Items" and the button open that pane); the PATH field
    ("Where grantd looks for commands"): Re-detect, then Apply restarts the service and an
    agent running `php --version` or another Homebrew tool works after an install from
    a Finder-launched app; Version shows `{version} · protocol 1`, and after replacing
    the app with a newer build Settings and the popover say "grantd was updated.
    Restart the background service to finish." with **Restart**.
22. Connect: both Copy buttons put exactly the displayed text on the clipboard;
    running the command in a new terminal registers the server; `/mcp` in Claude Code
    lists `secret_list`, `secret_exists`, `secret_masked`, `secret_run`; repeat with
    the app in a folder whose name contains a space and an apostrophe. **Test
    Connection** answers "grantd answered. Claude Code asks it the same way." with
    the service running and an error with it stopped.
23. Uninstall (Settings > Uninstall, or "Uninstall grantd..." in the app menu): each
    checkbox separately. Only "Stop and remove the background service" is ticked;
    ticking "Delete my vault: {n} secrets, {m} grants and the audit log" shows the
    warning and needs the typed word `delete` before **Remove** is enabled. Afterwards
    the plist, vault files and logs are gone as selected, the app is still there, the
    result says "The hardware key in your Keychain stays. It can't be exported and is
    useless without the vault file. grantd has no command to remove it yet.", shows
    `claude mcp remove grantd` with Copy and "To finish, drag grantd to the Trash."
    with **Reveal in Finder**. With weaker protection the Keychain checkbox appears and
    `security find-generic-password -s dev.grantd -a vault-kek` finds nothing after it.
24. Privacy: System Settings > Privacy & Security shows no Accessibility, Automation
    or Screen Recording request from grantd; `lsof -a -p <app pid> -i` shows no
    network sockets.
