#!/bin/sh
# Submit one file (a .zip of the app, or the .dmg) to Apple's notary service,
# wait for the verdict, and fail with the notary log if it is not Accepted.
# Called by make notarize and make dmg (docs/RELEASE.md).
#
#   usage: build/release/notarize.sh <file> <keychain-profile>
#
# The keychain profile is the name given to `xcrun notarytool store-credentials`
# (grantd-notary). The JSON result is kept next to the file as <file>.notary.json.
set -eu

[ $# -eq 2 ] || { echo "usage: $0 <file> <keychain-profile>" >&2; exit 2; }
file=$1
profile=$2
[ -f "$file" ] || { echo "notarize: $file is not a file" >&2; exit 2; }

result="$file.notary.json"
echo "notarize: submitting $file with keychain profile '$profile' (this waits, usually a few minutes)"

# notarytool exits non-zero for transport and credential errors; a finished but
# rejected submission is reported in "status", so both are checked.
if ! xcrun notarytool submit "$file" --keychain-profile "$profile" --wait --output-format json > "$result"; then
  echo "notarize: notarytool failed; its output:" >&2
  cat "$result" >&2
  echo "notarize: if the credentials are the problem, see docs/RELEASE.md (one-time notary setup)" >&2
  exit 1
fi

id=$(plutil -extract id raw -o - "$result")
status=$(plutil -extract status raw -o - "$result")
echo "notarize: submission $id finished with status: $status"

if [ "$status" != "Accepted" ]; then
  echo "notarize: not accepted; notary log for $id:" >&2
  xcrun notarytool log "$id" --keychain-profile "$profile" >&2 || true
  exit 1
fi
