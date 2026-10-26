#!/bin/sh
# Release preflight for the provisioning profile (make sign-release).
#
#   usage: build/release/check-profile.sh <profile> <team-id> <bundle-id> <keychain-group>
#
# A release profile must be a Developer ID profile, because the app runs on
# Macs that are not registered in the developer portal. A development profile
# lists devices (ProvisionedDevices) and would make AMFI kill the app at launch
# on every other Mac, even though signing and notarization would both succeed.
# Set ALLOW_DEV_PROFILE=1 to skip only that check (local signing tests).
set -eu

[ $# -eq 4 ] || { echo "usage: $0 <profile> <team-id> <bundle-id> <keychain-group>" >&2; exit 2; }
profile=$1 team=$2 bundle=$3 group=$4

fail() { echo "check-profile: $*" >&2; exit 1; }

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
plist=$dir/profile.plist

security cms -D -i "$profile" > "$plist" 2>/dev/null || fail "$profile is not a decodable provisioning profile"
plutil -lint "$plist" >/dev/null || fail "decoded profile is not a valid plist"

name=$(plutil -extract Name raw -o - "$plist")
pteam=$(plutil -extract TeamIdentifier.0 raw -o - "$plist")
[ "$pteam" = "$team" ] || fail "profile '$name' belongs to team '$pteam', want $team"

platform=$(plutil -extract Platform.0 raw -o - "$plist" 2>/dev/null || echo "")
[ "$platform" = "OSX" ] || fail "profile '$name' is for platform '$platform', want OSX"

exp=$(plutil -extract ExpirationDate raw -o - "$plist")
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# ISO 8601 UTC strings of the same shape compare correctly as strings.
[ "$exp" != "$now" ] && [ "$(printf '%s\n%s\n' "$now" "$exp" | sort | tail -n 1)" = "$exp" ] || fail "profile '$name' expired on $exp"

dump=$(plutil -p "$plist")
printf '%s\n' "$dump" | grep -Eq "\"com.apple.application-identifier\" => \"$team\.($bundle|\*)\"" \
  || fail "profile '$name' does not authorise application-identifier $team.$bundle (exact or $team.*)"
printf '%s\n' "$dump" | grep -Eq "\"($team\.$group|$team\.\*)\"" \
  || fail "profile '$name' does not carry keychain-access-groups covering $team.$group (exact or $team.*)"

devices=no
plutil -extract ProvisionedDevices raw -o - "$plist" >/dev/null 2>&1 && devices=yes
all=$(plutil -extract ProvisionsAllDevices raw -o - "$plist" 2>/dev/null || echo false)
if [ "$devices" = yes ] || [ "$all" != true ]; then
  if [ "${ALLOW_DEV_PROFILE:-}" = 1 ]; then
    echo "check-profile: WARNING: '$name' is a device-limited (development) profile; a build signed with it will not launch on other Macs (ALLOW_DEV_PROFILE=1)" >&2
  else
    fail "profile '$name' is device-limited (ProvisionedDevices set or ProvisionsAllDevices not true): not a Developer ID profile. Download the Developer ID profile for App ID $bundle, or set ALLOW_DEV_PROFILE=1 for a local test"
  fi
fi
echo "check-profile: '$name' ok (team $team, expires $exp)"
