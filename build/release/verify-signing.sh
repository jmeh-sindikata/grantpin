#!/bin/sh
# Post-signing checks for a release bundle (make sign-release).
#
#   usage: build/release/verify-signing.sh <app> <helper-app> <team-id> [<archs>]
#
# Fails unless, for the outer app and the nested helper app:
#  - the signature verifies (--deep --strict) and carries a secure timestamp,
#  - the hardened runtime flag is set (flags=0x10000(runtime)),
#  - the authority is a Developer ID Application certificate of <team-id>,
#  - the entitlements are exactly com.apple.application-identifier and
#    keychain-access-groups: no hardened-runtime exception (com.apple.security.cs.*),
#    no get-task-allow, no sandbox,
#  - both bundles embed the same provisioning profile,
# and, when <archs> is given (make passes "x86_64 arm64" for a universal release),
# unless both main executables have exactly those architectures (lipo -archs),
# and unless the only Mach-O files in the app are the two main executables, so
# a binary added later cannot ship unsigned by accident.
set -eu

[ $# -eq 3 ] || [ $# -eq 4 ] || { echo "usage: $0 <app> <helper-app> <team-id> [<archs>]" >&2; exit 2; }
app=$1 helper=$2 team=$3 archs=${4:-}

fail() { echo "verify-signing: $*" >&2; exit 1; }

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

app_exe=$app/Contents/MacOS/grantpin-app
helper_exe=$helper/Contents/MacOS/grantpin

# 1. Every Mach-O in the tree is one of the two main executables, which codesign
#    seals as part of signing their bundle.
find "$app" -type f | while IFS= read -r f; do
  if file -b "$f" | grep -q "Mach-O"; then
    [ "$f" = "$app_exe" ] || [ "$f" = "$helper_exe" ] \
      || { echo "verify-signing: unexpected Mach-O $f: add it to the inside-out signing in the Makefile" >&2; exit 1; }
  fi
done || exit 1

# 2. Signature, flags, authority, timestamp and entitlements of each bundle.
for b in "$app" "$helper"; do
  codesign --verify --deep --strict --verbose=2 "$b" || fail "$b does not verify"
  info=$dir/info.txt
  codesign -dv --verbose=4 "$b" > "$info" 2>&1
  grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\(.*runtime.*\)' "$info" || { cat "$info" >&2; fail "$b: hardened runtime flag missing"; }
  grep -q '^Authority=Developer ID Application:' "$info" || fail "$b: not signed by a Developer ID Application certificate"
  grep -q "^TeamIdentifier=$team\$" "$info" || fail "$b: TeamIdentifier is not $team"
  grep -q '^Timestamp=' "$info" || fail "$b: no secure timestamp (do not use --timestamp=none for a release)"
  grep -q '^Signature=adhoc' "$info" && fail "$b: ad-hoc signature"
  codesign -d --entitlements - --xml "$b" > "$dir/ent.plist" 2>/dev/null
  plutil -lint "$dir/ent.plist" >/dev/null || fail "$b: entitlements are not a valid plist"
  keys=$(plutil -p "$dir/ent.plist" | sed -n 's/^  "\([^"]*\)" =>.*/\1/p' | sort | tr '\n' ' ')
  want="com.apple.application-identifier keychain-access-groups "
  [ "$keys" = "$want" ] || fail "$b: entitlement keys are '$keys', want '$want'"
  echo "verify-signing: $b: runtime, Developer ID $team, timestamped, entitlements: $keys"
done

# 3. Architectures of the two main executables (universal release).
if [ -n "$archs" ]; then
  "$(dirname "$0")/check-archs.sh" "$archs" "$app_exe" "$helper_exe" || fail "architectures are not '$archs'"
fi

# 4. One profile in both bundles.
cmp -s "$app/Contents/embedded.provisionprofile" "$helper/Contents/embedded.provisionprofile" \
  || fail "the two embedded.provisionprofile files differ or are missing"
echo "verify-signing: ok"
