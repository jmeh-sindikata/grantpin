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
is the working path for a from-source build.

### 2b. Verify the key exists

- Fallback item (login keychain): `security find-generic-password -s dev.grantd -a vault-kek`
  (add `-g` to print the secret to the terminal; do not do that on a screen
  you share). Keychain Access.app shows it under "login" -> Passwords.
- Secure Enclave key and any item in the **data-protection keychain**: these are
  deliberately invisible to the `security` CLI and Keychain Access. The
  evidence they exist is that `New()` reports `Mode() == "secure-enclave"` and
  Unwrap of an old blob still works from a new process (section 2 does this).

### 2c. Remove the real vault key (destructive)

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
