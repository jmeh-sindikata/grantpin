# Releasing grantpin (Developer ID, notarized DMG)

`make release` turns a clean checkout into `dist/grantpin-<version>.dmg`: a
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
3. **Developer ID provisioning profile** for the App ID `dev.grantpin.app` with
   Keychain Sharing (developer portal, Profiles, Distribution, Developer ID).
   It is what authorises `keychain-access-groups`, and so the Secure Enclave,
   on other people's Macs. There is no default path: pass it as `PROFILE=`.
   `make sign-release` checks it before signing (team, App ID, keychain group,
   not expired, and that it is a Developer ID profile, not a device-limited
   development profile; a development profile signs fine but the app is then
   killed at launch on every Mac that is not registered in the profile).
   **The project was renamed from grantd on 2026-10-26, so the profile has to be
   re-issued for the App ID `dev.grantpin.app`** (register the new App ID with
   Keychain Sharing, then create a new Developer ID profile for it). The old
   `~/Downloads/grantd_developer_id.provisionprofile` is for `dev.grantd.app`
   and fails `check-profile.sh`. The team, `MT2QHQX6PS`, and the signing
   identity are unchanged.
4. **Notary credentials**, stored once in the login keychain under the profile
   name `grantpin-notary` (override with `NOTARY_PROFILE=`). Pick one:

   - Apple ID with an app-specific password. Create the password at
     account.apple.com (Sign-In and Security, App-Specific Passwords), then:

     ```sh
     xcrun notarytool store-credentials grantpin-notary \
       --apple-id <your-apple-id> --team-id MT2QHQX6PS
     ```

     It prompts for the password (do not put it on the command line) and
     validates the credentials against Apple before saving them.
   - App Store Connect API key (better for a shared or automated setup).
     Create a key in App Store Connect (Users and Access, Integrations), download
     the `.p8` once, then:

     ```sh
     xcrun notarytool store-credentials grantpin-notary \
       --key /path/to/AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-uuid>
     ```

     (Omit `--issuer` for an individual key.)

   Check later with `xcrun notarytool history --keychain-profile grantpin-notary`.

## Release

```sh
git tag v0.2.0          # optional, see "Version" below
make release PROFILE=/path/to/Developer_ID.provisionprofile
```

`make release` stops at the first failure and runs, in order:

| Step | Target | What it does |
| --- | --- | --- |
| 0 | `release-check` | PROFILE, identity, clean tree, notary credentials (a read-only `notarytool history`); no submission. |
| 1 | `bundle` | Builds the Go helper for macOS 14 and `dist/stage.noindex/grantpin.app` (unsigned), both universal (`UNIVERSAL=1`, see "Universal build"), and checks both Info.plists carry the version and both executables are `x86_64 arm64`. |
| 2 | `sign-release` | Embeds the profile and signs inside out with `--options runtime --timestamp`: helper `.app`, then outer `.app` (which also seals each bundle's main executable). No `--deep`. Then `build/release/verify-signing.sh` checks both bundles, including `lipo -archs` of both main executables. |
| 3 | `notarize` | `ditto -c -k --keepParent` of the app, `notarytool submit --wait`, on failure prints `notarytool log`, then `stapler staple` and `stapler validate` the app. |
| 4 | `dmg` | Stages `grantpin.app` (in `dist/stage.noindex/dmg-stage`), an `Applications` symlink and the committed Finder layout (`.DS_Store`), `hdiutil create -volname grantpin -format UDZO`, signs the DMG, notarizes it, staples it. |
| 5 | `verify-release` | `spctl -a -vv -t install dist/stage.noindex/grantpin.app`, `spctl -a -vv -t exec dist/stage.noindex/grantpin.app`, `spctl -a -vv -t open --context context:primary-signature dist/grantpin-<version>.dmg`, and `stapler validate` on both, plus `lipo -archs` of both executables. Each must say `accepted` with `source=Notarized Developer ID`. |

Each step is also a target, so a failed release resumes where it stopped:

```sh
make sign-release PROFILE=/path/to/Developer_ID.provisionprofile
make notarize [NOTARY_PROFILE=grantpin-notary]
make dmg
make verify-release
```

Output: `dist/grantpin-<version>.dmg`, plus `dist/grantpin-notarize.zip.notary.json`
and `dist/grantpin-<version>.dmg.notary.json` (the notary submissions, with their IDs).
Fetch a log later with `xcrun notarytool log <id> --keychain-profile grantpin-notary`.

### Where the unsigned app copies live (`.noindex`)

Builds leave unsigned, ad-hoc signed copies of the app that share the installed
app's bundle ID `dev.grantpin.app`. Spotlight indexed them, and macOS can open the
wrong copy by bundle ID (it did, after a `brew upgrade`, with the "Move grantpin to
your Applications folder first" banner). macOS skips directories whose name ends in
`.noindex`, so every directory that holds an app bundle now does:

| Was | Now |
| --- | --- |
| `build/xcode/` (xcodebuild derived data) | `build/xcode.noindex/` |
| `dist/grantpin.app` | `dist/stage.noindex/grantpin.app` |
| `dist/dmg-stage/` | `dist/stage.noindex/dmg-stage/` |

`dist/grantpin-<version>.dmg` and its `.notary.json` stay where they were. After a
release, the signed and stapled app also stays in `dist/stage.noindex/`; run
`make clean-apps` to delete everything under `build/xcode.noindex` and
`dist/stage.noindex` (and any pre-`.noindex` leftovers at the old paths). It touches
nothing outside the repo, never `/Applications`. Do not run an app from these folders
for real use; install from the DMG.

### DMG window layout

`build/release/dmg/DS_Store` is copied into the image as `.DS_Store`, so Finder
opens the DMG as a compact 600x400 icon view (no sidebar, toolbar or status bar)
with `grantpin.app` and `Applications` side by side, instead of the default large
window. It is generated by `build/release/dmg-layout.py` and committed (a small
binary) so that `make dmg` needs no Python and no Finder automation, which would
show a macOS permission dialog. Regenerate only when the layout changes:

```sh
pip install ds_store mac_alias
python3 build/release/dmg-layout.py build/release/dmg/DS_Store
```

The volume name (`grantpin`) and the app name (`grantpin.app`) are part of the layout;
change them together.

### Why both the app and the DMG are notarized

Notarizing the app is what makes Gatekeeper accept `grantpin.app` once it has been
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
`keychain-access-groups` (`build/bundle/grantpin-app.entitlements`, expanded by
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

## Universal build (arm64 + x86_64)

The release is one fat app that runs natively on Apple Silicon and Intel Macs.
`make release`, `make sign-release` and `make verify-release` set `UNIVERSAL=1` by
default; `make bundle UNIVERSAL=1` does the same for a bundle you build by hand.
A plain `make build` and `make bundle` stay host-only and fast (about 11 s vs 33 s
for a bundle on a warm cache). `UNIVERSAL=0` on the release targets is for a
host-only dry run (the architecture checks are then skipped).

- **Go helper** (`make helper-universal`): `cmd/grantpin` is cgo (Objective-C for the
  Secure Enclave and LocalAuthentication), so each slice is built with
  `CGO_ENABLED=1 GOARCH=<arm64|amd64> CC="clang -arch <arm64|x86_64>"`, the SDK from
  `xcrun --sdk macosx --show-sdk-path` as `SDKROOT`, and
  `MACOSX_DEPLOYMENT_TARGET`/`-mmacosx-version-min` = `MIN_MACOS` (14.0). Xcode's
  clang cross-compiles for both on either kind of Mac. The slices are merged
  with `lipo -create` into `bin/grantpin`, and each slice's `minos` is checked
  before the merge.
- **SwiftUI app**: `xcodebuild ... ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO`.
- **Checks**: `build/release/check-archs.sh` (`lipo -archs` of `grantpin-app` and
  `grantpin-daemon.app/Contents/MacOS/grantpin` must be `x86_64 arm64`) runs at the end of
  `make bundle UNIVERSAL=1`, inside `verify-signing.sh` and in `make verify-release`.
- **Testing the Intel slice** on an Apple Silicon Mac needs Rosetta:
  `arch -x86_64 dist/stage.noindex/grantpin.app/Contents/Helpers/grantpin-daemon.app/Contents/MacOS/grantpin --version`.
  Rosetta does not exercise the hardware keystore: only a real Intel Mac with a T2
  chip tests the Secure Enclave path on x86_64.
- `lipo` output is a fat file, which `go build -o bin/grantpin` refuses to overwrite;
  `make build` and `make helper` delete `bin/grantpin` first.

## Version

`VERSION` comes from `make VERSION=x`, else `git describe --tags --always --dirty`,
else a `VERSION` file, else `dev` (see MANUAL-TEST-MACOS.md 2c). It is what
`grantpin --version` and `grantpin status` report, verbatim. A release is refused when
the version ends in `-dirty` (`ALLOW_DIRTY=1` for a dry run).

What lands in the bundle and the DMG name depends on whether `VERSION` looks like a
version number, `vX.Y.Z` or `X.Y.Z`, optionally followed by git describe's
`-N-gHASH` and `-dirty`:

| `VERSION` | `CFBundleShortVersionString` | `CFBundleVersion` | DMG |
| --- | --- | --- | --- |
| `v0.2.0` (clean tag) | `0.2.0` | `0.2.0` | `grantpin-0.2.0.dmg` |
| `v0.2.0-3-gabc1234` (after a tag) | `0.2.0` | `0.2.0` | `grantpin-v0.2.0-3-gabc1234.dmg` |
| `b83ad79`, `dev` (no tag) | `b83ad79` | commit count | `grantpin-b83ad79.dmg` |

Both Info.plists (outer app and helper) get the same values, and `make bundle` fails
if they disagree. `CFBundleVersion` is only `X.Y.Z`, not `X.Y.Z.N`: Apple allows at
most three numeric components there, so the `-N` commit count is not appended.
Tag first (`git tag v0.2.0`) for a numeric version and a clean DMG name. To see the
computed values without a build: `make -pn VERSION=v0.2.0 | grep -E '^(BUNDLE_VERSION|BUNDLE_BUILD|DMG) '`.

## What to tell testers

- The DMG is for Macs with macOS 14 or later, Apple Silicon or Intel (the app and
  the helper inside are universal, arm64 + x86_64).
- Open the DMG and drag grantpin to Applications. Eject the DMG.
- Open grantpin from Applications. There is no Dock icon: grantpin lives in the menu
  bar. The first time, macOS may say it was downloaded from the Internet; choose
  Open.
- The Welcome window walks through the rest: it installs the background service
  (the daemon, as a launch agent), creates the vault, adds a first secret, and
  shows the Connect panel with the command that connects Claude Code.
- There is no auto-update. To update, quit grantpin, download the new DMG, and drag
  the app over the old one, then check Settings (or the menu-bar popover) that the
  service is running. Secrets and the vault are in
  `~/Library/Application Support/grantpin` and are not touched. Not tested: an
  update over a running install.

## Verify a downloaded DMG

On the Mac that downloaded it (so the quarantine flag is set):

```sh
spctl -a -vv -t open --context context:primary-signature grantpin-<version>.dmg
#   accepted, source=Notarized Developer ID, origin=Developer ID Application: S.A.P. SH.P.K. (MT2QHQX6PS)
xcrun stapler validate grantpin-<version>.dmg
#   The validate action worked!
hdiutil attach grantpin-<version>.dmg
spctl -a -vv -t exec /Volumes/grantpin/grantpin.app
codesign -dv --verbose=4 /Volumes/grantpin/grantpin.app 2>&1 | grep -E 'flags|Authority|TeamIdentifier'
#   flags=0x10000(runtime), Developer ID Application ... (MT2QHQX6PS)
codesign -d --entitlements - /Volumes/grantpin/grantpin.app/Contents/Helpers/grantpin-daemon.app
hdiutil detach /Volumes/grantpin
```

Publish a checksum next to the download: `shasum -a 256 grantpin-<version>.dmg`.

## Update the Homebrew tap

The last step of a release, once the DMG is attached to the GitHub release:
in the `homebrew-grantpin` repo (the tap `jmeh-sindikata/grantpin`) run
`bin/bump X.Y.Z`, review the diff, commit, push. `bin/bump` downloads the
release DMG, computes its sha256 and rewrites `version` and `sha256` in
`Casks/grantpin.rb`.

## Troubleshooting

- **Notarization `Invalid`.** The log is printed. Usual causes: a binary that is
  not signed with the hardened runtime and a secure timestamp, or a
  `get-task-allow` entitlement. `verify-signing.sh` catches both beforehand.
- **App is killed at launch on another Mac (exit 137, `amfid`: `No matching
  profile found`).** The embedded profile is a development profile, or does not
  cover `dev.grantpin.app` and `MT2QHQX6PS.dev.grantpin`. Use the Developer ID
  profile; `check-profile.sh` refuses the wrong kind.
- **Keychain prompt while signing.** `codesign` asks once for access to the
  Developer ID private key; choose Always Allow to stop it asking again.
- **`hdiutil: WARNING ... is deprecated`.** `hdiutil create` still works; Apple
  points to `diskutil image create`. Switching is a backlog item.
