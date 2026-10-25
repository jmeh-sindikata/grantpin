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
- The **approver** prompts exactly once per `Ask`.
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

### 2a. If `TestManualSecureEnclaveRoundTrip` fails with `OSStatus -34018`

`errSecMissingEntitlement`. A permanent Secure Enclave key lives in the
data-protection keychain, which macOS only opens to binaries carrying a
`keychain-access-groups` / `application-identifier` entitlement (a signed
binary plus provisioning profile). A plain `go build` / `go test` binary is
unsigned and usually does not have it. This is the single biggest open risk of
step 7: record the exact error in your report. Options, in order:

1. Sign the real `grantd` binary with a Developer ID or Apple Development
   identity and an entitlements plist containing the keychain access group, then
   re-run the checks against that binary (the `go test` binary can be signed the
   same way: `go test -c` then `codesign`).
2. Use the fallback (section 6) knowing it is weaker.

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

```sh
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualPromptsOnce
```

Expected: one system sheet with Touch ID, reading roughly
*grantd-manual-test wants to run `echo hello` with MANUAL_TEST_SECRET in
/tmp/grantd-manual-test (no policy)*, a **Deny** button (the cancel label) and
a "Use Password..." button. Check:

1. Touch the sensor -> test logs `decision={Allow:true TTL:0s ...}`.
2. Re-run, click **Deny** -> `decision={Allow:false ... Reason:user denied}`, `err=<nil>`.
3. Re-run, choose "Use Password...", type a **wrong** password -> macOS keeps
   the sheet open for retries; after it gives up the test logs
   `Allow:false Reason:authentication failed`. Typing the right password -> Allow.
4. Re-run and check the wording. LocalAuthentication frames the text as
   `"<app>" is trying to <reason>`; if it reads badly we will reword
   `BuildReason` in `internal/approve/darwin/reason.go` (note this in the report).

To assert instead of eyeball: `GRANTD_MANUAL_EXPECT=allow` or `=deny`.

```sh
GRANTD_MANUAL_TEST=1 go test -count=1 -v ./internal/approve/darwin -run TestManualCancelViaContext
```

Expected: the prompt appears, then disappears by itself after about 3 seconds
and the test passes (`context.DeadlineExceeded`, never an allow).

## 4. Expected behaviour on edge cases

| Situation | Expected |
|---|---|
| Cancel / Deny / Esc | `Decision{Allow:false, Reason:"user denied"}`, no error |
| Wrong password | sheet retries; after the system gives up: deny, reason `authentication failed` |
| Touch ID locked out (too many failures) | sheet asks for the password directly (policy is DeviceOwnerAuthentication) |
| Lid closed, clamshell with external display, or Mac without Touch ID | the password sheet is used; this still counts as TierHardware per HANDOFF §5 table |
| No device passcode/password set | `errors.Is(err, ErrUnavailable)`; never an allow |
| Screen locked / fast user switch mid-prompt | `errors.Is(err, ErrInterrupted)`; no decision |
| No GUI session (SSH, headless launchd) | `errors.Is(err, ErrNoGUISession)` immediately, no prompt |
| `ctx` cancelled while the prompt is up | prompt is invalidated, `ctx.Err()` returned |
| Agent shell tries to influence it (env vars, files, stdin, socket) | nothing reads those; only the system sheet decides |

## 5. Known limits to confirm or record

- **Allow once only.** LocalAuthentication has no three-button UI, so v0.1 is
  Allow-once on success and Deny otherwise. `WithDefaultTTL(d)` lets the daemon
  opt into "Allow for N" (the prompt then states the duration), but a real
  Allow once / Allow for N / Deny chooser is not implemented.
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
