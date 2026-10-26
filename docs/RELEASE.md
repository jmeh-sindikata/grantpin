# Releasing grantd (Developer ID, notarized DMG)

`make release` turns a clean checkout into `dist/grantd-<version>.dmg`: a
Developer ID signed, hardened-runtime, notarized and stapled disk image that
opens on any Mac running macOS 14 or later without a Gatekeeper warning. This
page is the whole flow for a human. The mechanics of the bundle itself (nested
helper, profile, entitlements) are in
[MANUAL-TEST-MACOS.md](MANUAL-TEST-MACOS.md) section 2c.

Nothing here is part of `make ci`. CI only has to keep `make bundle` building.

## Prerequisites (once)

1. **Xcode and Go.** `make bundle` runs `xcodebuild` and `go build` (cgo).
2. **Signing identity.** `Developer ID Application: S.A.P. SH.P.K. (MT2QHQX6PS)`
   in the login keychain. Check:
   `security find-identity -v -p codesigning | grep "Developer ID Application"`.
   Another identity: `make release RELEASE_IDENTITY="..." RELEASE_TEAM_ID=...`.
3. **Developer ID provisioning profile** for the App ID `dev.grantd.app` with
   Keychain Sharing (developer portal, Profiles, Distribution, Developer ID).
   It is what authorises `keychain-access-groups`, and so the Secure Enclave,
   on other people's Macs. There is no default path: pass it as `PROFILE=`.
   `make sign-release` checks it before signing (team, App ID, keychain group,
   not expired, and that it is a Developer ID profile, not a device-limited
   development profile; a development profile signs fine but the app is then
   killed at launch on every Mac that is not registered in the profile).
4. **Notary credentials**, stored once in the login keychain under the profile
   name `grantd-notary` (override with `NOTARY_PROFILE=`). Pick one:

   - Apple ID with an app-specific password. Create the password at
     account.apple.com (Sign-In and Security, App-Specific Passwords), then:

     ```sh
     xcrun notarytool store-credentials grantd-notary \
       --apple-id <your-apple-id> --team-id MT2QHQX6PS
     ```

     It prompts for the password (do not put it on the command line) and
     validates the credentials against Apple before saving them.
   - App Store Connect API key (better for a shared or automated setup).
     Create a key in App Store Connect (Users and Access, Integrations), download
     the `.p8` once, then:

     ```sh
     xcrun notarytool store-credentials grantd-notary \
       --key /path/to/AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-uuid>
     ```

     (Omit `--issuer` for an individual key.)

   Check later with `xcrun notarytool history --keychain-profile grantd-notary`.

## Release

```sh
git tag v0.2.0          # optional, see "Version" below
make release PROFILE=/path/to/Developer_ID.provisionprofile
```

`make release` stops at the first failure and runs, in order:

| Step | Target | What it does |
| --- | --- | --- |
| 0 | `release-check` | PROFILE, identity, clean tree, notary credentials (a read-only `notarytool history`); no submission. |
| 1 | `bundle` | Builds the Go helper for macOS 14 and `dist/grantd.app` (unsigned), and checks both Info.plists carry the version. |
| 2 | `sign-release` | Embeds the profile and signs inside out with `--options runtime --timestamp`: helper `.app`, then outer `.app` (which also seals each bundle's main executable). No `--deep`. Then `build/release/verify-signing.sh` checks both bundles. |
| 3 | `notarize` | `ditto -c -k --keepParent` of the app, `notarytool submit --wait`, on failure prints `notarytool log`, then `stapler staple` and `stapler validate` the app. |
| 4 | `dmg` | Stages `grantd.app` and an `Applications` symlink, `hdiutil create -volname grantd -format UDZO`, signs the DMG, notarizes it, staples it. |
| 5 | `verify-release` | `spctl -a -vv -t install dist/grantd.app`, `spctl -a -vv -t exec dist/grantd.app`, `spctl -a -vv -t open --context context:primary-signature dist/grantd-<version>.dmg`, and `stapler validate` on both. Each must say `accepted` with `source=Notarized Developer ID`. |

Each step is also a target, so a failed release resumes where it stopped:

```sh
make sign-release PROFILE=/path/to/Developer_ID.provisionprofile
make notarize [NOTARY_PROFILE=grantd-notary]
make dmg
make verify-release
```

Output: `dist/grantd-<version>.dmg`, plus `dist/grantd-notarize.zip.notary.json`
and `dist/grantd-<version>.dmg.notary.json` (the notary submissions, with their IDs).
Fetch a log later with `xcrun notarytool log <id> --keychain-profile grantd-notary`.

### Why both the app and the DMG are notarized

Notarizing the app is what makes Gatekeeper accept `grantd.app` once it has been
copied out of the DMG. A DMG can only carry a stapled ticket if it was notarized
itself, and a stapled DMG is accepted offline and shows no warning of its own.
This is the conservative choice (Apple does not require the DMG to be notarized
when the app inside is). The order matters: the app is notarized and stapled first, so the DMG contains the
stapled app (a stapled app keeps working offline after being dragged out). This
costs one extra submission of a couple of minutes.

### Hardened runtime and entitlements

Both binaries are signed with `--options runtime` and **no hardened-runtime
exception entitlements**. The only entitlements are the two that the profile
backs and the Secure Enclave depends on: `com.apple.application-identifier` and
`keychain-access-groups` (`build/bundle/grantd-app.entitlements`, expanded by
`make sign-bundle`). `verify-signing.sh` fails the release if anything else
appears, in particular `get-task-allow` (notarization rejects it) or any
`com.apple.security.cs.*` key.

| Exception | Needed? | Evidence |
| --- | --- | --- |
| `allow-jit`, `allow-unsigned-executable-memory` | No | Go emits no code at run time and the repo has no `MAP_JIT` or `PROT_EXEC`; the SwiftUI app does neither. A hardened-runtime build of the vault test binary (SQLite, crypto) passes. |
| `disable-library-validation` | No | `otool -L` of both binaries lists only `/System/Library` and `/usr/lib` libraries (the Swift runtime is the OS one in `/usr/lib/swift`), and nothing calls `dlopen`. |
| `allow-dyld-environment-variables` | No | Nothing relies on `DYLD_*`. |
| `automation.apple-events` | No | The approval dialog runs `/usr/bin/osascript` as a child and sends no event to another app. |

Add an exception only when a signed build fails without it, with the failing
evidence in the comment in `sign-bundle`.

## Version

`VERSION` comes from `make VERSION=x`, else `git describe --tags --always --dirty`,
else a `VERSION` file, else `dev` (see MANUAL-TEST-MACOS.md 2c). It names the DMG and
is stamped as `CFBundleShortVersionString` (and the commit count as
`CFBundleVersion`) in both Info.plists; `make bundle` fails if they disagree. A
release is refused when the version ends in `-dirty` (`ALLOW_DIRTY=1` for a dry
run). Tag first (`git tag v0.2.0`) for a readable DMG name. The tag is used
verbatim (`v0.2.0`), and between tags `git describe` gives `v0.2.0-3-gabc123`.

## What to tell testers

- The DMG is for Macs with macOS 14 or later, on the CPU type it was built on
  (`make app` builds for the host architecture only: an Apple Silicon build does
  not run on Intel Macs).
- Open the DMG and drag grantd to Applications. Eject the DMG.
- Open grantd from Applications. There is no Dock icon: grantd lives in the menu
  bar. The first time, macOS may say it was downloaded from the Internet; choose
  Open.
- The Welcome window walks through the rest: it installs the background service
  (the daemon, as a launch agent), creates the vault, adds a first secret, and
  shows the Connect panel with the command that connects Claude Code.
- There is no auto-update. To update, quit grantd, download the new DMG, and drag
  the app over the old one, then check Settings (or the menu-bar popover) that the
  service is running. Secrets and the vault are in
  `~/Library/Application Support/grantd` and are not touched. Not tested: an
  update over a running install.

## Verify a downloaded DMG

On the Mac that downloaded it (so the quarantine flag is set):

```sh
spctl -a -vv -t open --context context:primary-signature grantd-<version>.dmg
#   accepted, source=Notarized Developer ID, origin=Developer ID Application: S.A.P. SH.P.K. (MT2QHQX6PS)
xcrun stapler validate grantd-<version>.dmg
#   The validate action worked!
hdiutil attach grantd-<version>.dmg
spctl -a -vv -t exec /Volumes/grantd/grantd.app
codesign -dv --verbose=4 /Volumes/grantd/grantd.app 2>&1 | grep -E 'flags|Authority|TeamIdentifier'
#   flags=0x10000(runtime), Developer ID Application ... (MT2QHQX6PS)
codesign -d --entitlements - /Volumes/grantd/grantd.app/Contents/Helpers/grantd-daemon.app
hdiutil detach /Volumes/grantd
```

Publish a checksum next to the download: `shasum -a 256 grantd-<version>.dmg`.

## Troubleshooting

- **Notarization `Invalid`.** The log is printed. Usual causes: a binary that is
  not signed with the hardened runtime and a secure timestamp, or a
  `get-task-allow` entitlement. `verify-signing.sh` catches both beforehand.
- **App is killed at launch on another Mac (exit 137, `amfid`: `No matching
  profile found`).** The embedded profile is a development profile, or does not
  cover `dev.grantd.app` and `MT2QHQX6PS.dev.grantd`. Use the Developer ID
  profile; `check-profile.sh` refuses the wrong kind.
- **Keychain prompt while signing.** `codesign` asks once for access to the
  Developer ID private key; choose Always Allow to stop it asking again.
- **`hdiutil: WARNING ... is deprecated`.** `hdiutil create` still works; Apple
  points to `diskutil image create`. Switching is a backlog item.
