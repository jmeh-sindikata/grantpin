#!/bin/sh
# Xcode Run Script phase "Embed grantpin helper" (docs/UI-SPEC.md 5.2).
#
# Builds Contents/Helpers/grantpin-daemon.app inside the app being built from
# ../bin/grantpin (make helper) and ../build/bundle/helper-Info.plist. The
# helper is NOT signed here: there is one signing path, make sign-bundle.
#
# Variables come from the build settings (make app passes them):
#   DAEMON_BUNDLE_ID   bundle id of the helper, dev.grantpin.app.daemon
#   MARKETING_VERSION, CURRENT_PROJECT_VERSION   shown version and build number
#   DAEMON_MIN_MACOS   LSMinimumSystemVersion of the helper, 14.0
set -eu

SRC_BIN="$SRCROOT/../bin/grantpin"
TEMPLATE="$SRCROOT/../build/bundle/helper-Info.plist"
HELPER="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers/grantpin-daemon.app"

[ -x "$SRC_BIN" ] || { echo "error: $SRC_BIN missing: run make helper" >&2; exit 1; }
[ -f "$TEMPLATE" ] || { echo "error: $TEMPLATE missing" >&2; exit 1; }
: "${DAEMON_BUNDLE_ID:?}" "${MARKETING_VERSION:?}" "${CURRENT_PROJECT_VERSION:?}" "${DAEMON_MIN_MACOS:?}"

rm -rf "$HELPER"
mkdir -p "$HELPER/Contents/MacOS"
cp "$SRC_BIN" "$HELPER/Contents/MacOS/grantpin"
sed -e '/<!--/,/-->/d' \
    -e "s|@BUNDLE_ID@|$DAEMON_BUNDLE_ID|g" \
    -e "s|@VERSION@|$MARKETING_VERSION|g" \
    -e "s|@BUILD@|$CURRENT_PROJECT_VERSION|g" \
    -e "s|@MIN_MACOS@|$DAEMON_MIN_MACOS|g" \
    "$TEMPLATE" > "$HELPER/Contents/Info.plist"
plutil -lint "$HELPER/Contents/Info.plist"
