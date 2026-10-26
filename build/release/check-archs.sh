#!/bin/sh
# Fails unless every given Mach-O has exactly the expected architectures.
#
#   usage: build/release/check-archs.sh "<archs>" <macho>...
#   e.g.   build/release/check-archs.sh "x86_64 arm64" dist/grantd.app/Contents/MacOS/grantd-app
#
# Order does not matter ("arm64 x86_64" equals "x86_64 arm64"). Used by make bundle
# (UNIVERSAL=1), build/release/verify-signing.sh and make verify-release.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 \"<archs>\" <macho>..." >&2; exit 2; }
raw=$1
want=$(printf '%s\n' $raw | sort | tr '\n' ' ')
shift

for f in "$@"; do
  [ -f "$f" ] || { echo "check-archs: $f missing" >&2; exit 1; }
  got=$(lipo -archs "$f")
  norm=$(printf '%s\n' $got | sort | tr '\n' ' ')
  [ "$norm" = "$want" ] || { echo "check-archs: $f has architectures '$got', want '$raw'" >&2; exit 1; }
  echo "check-archs: $f: $got"
done
