# grantd Makefile. `make ci` is exactly what CI runs.
GO        ?= go
STATICCHECK ?= staticcheck
DEV_TAG   := grantd_dev
# Version, first match wins: VERSION=x on the command line, git describe, the
# contents of a VERSION file (written by `make dist-src` so a git archive export
# still carries the hash), then "dev".
ifeq ($(origin VERSION),command line)
VERSION_SRC := command line
else ifneq ($(shell git describe --tags --always --dirty 2>/dev/null),)
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null)
VERSION_SRC := git
else ifneq ($(wildcard VERSION),)
VERSION     := $(shell cat VERSION)
VERSION_SRC := VERSION file
else
VERSION     := dev
VERSION_SRC := default
endif
LDFLAGS   := -X main.version=$(VERSION)

# Signed .app bundle (docs/UI-SPEC.md section 5; docs/MANUAL-TEST-MACOS.md 2c).
# The app is two bundles: the outer grantd.app (SwiftUI menu-bar app, built by
# xcodebuild from app/) and, inside it, Contents/Helpers/grantd-daemon.app
# whose main executable is the Go binary. BUNDLE_ID is the outer bundle's
# identifier and the single place it lives; it must match the App ID in the
# developer portal. The helper's is BUNDLE_ID.daemon. KEYCHAIN_GROUP is the
# keychain access group, without the team prefix. MIN_MACOS is the lowest macOS
# for both (the Go binary is built for it, see `make helper`). None of this is
# part of `make ci`; `make ci-app` is the app counterpart.
BUNDLE_ID      ?= dev.grantd.app
KEYCHAIN_GROUP ?= dev.grantd
MIN_MACOS      ?= 14.0
APP            := dist/grantd.app
HELPER_APP     := $(APP)/Contents/Helpers/grantd-daemon.app
APP_PRODUCT    := build/xcode/Build/Products/Release/grantd-app.app
BUILD_NUMBER   ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 1)
# codesign timestamp option; use CODESIGN_TIMESTAMP=--timestamp=none offline.
CODESIGN_TIMESTAMP ?= --timestamp
# Go helper: cgo must target MIN_MACOS or the binary records the build
# machine's macOS as its minimum (minos) and will not start on older releases.
HELPER_ENV     := CGO_ENABLED=1 CGO_CFLAGS=-mmacosx-version-min=$(MIN_MACOS) CGO_LDFLAGS=-mmacosx-version-min=$(MIN_MACOS)

# Universal (arm64 + x86_64) bundle, so one DMG runs on Apple Silicon and Intel
# Macs. UNIVERSAL=1 makes `make bundle` (and `make app`) build the Go helper for
# both architectures and merge them with lipo (`make helper-universal`), and the
# SwiftUI app for both with xcodebuild. It is off for a plain `make bundle`
# (fast, host architecture only, for development) and on for the release path:
# `make release`, `make sign-release` and `make verify-release` default it to 1
# (RELEASE_UNIVERSAL; pass UNIVERSAL=0 for a deliberate host-only dry run).
# Each Go slice is cross-built with CC="clang -arch <arch>" (Xcode's clang is a
# cross compiler for both), the macOS SDK from xcrun, and MIN_MACOS as above.
UNIVERSAL         ?=
RELEASE_UNIVERSAL := $(if $(UNIVERSAL),$(UNIVERSAL),1)
ifeq ($(UNIVERSAL),1)
APP_ARCHS      := arm64 x86_64
HELPER_DEP     := helper-universal
EXPECT_ARCHS   := x86_64 arm64
else
APP_ARCHS      := $(shell uname -m)
HELPER_DEP     := helper
EXPECT_ARCHS   :=
endif

# Release (Developer ID, notarized DMG; docs/RELEASE.md). RELEASE_IDENTITY must
# be a Developer ID Application certificate in the keychain; PROFILE (the
# Developer ID provisioning profile) has no default on purpose, pass it.
# NOTARY_PROFILE is the keychain profile made once with
# `xcrun notarytool store-credentials`. A release is never built from a dirty
# tree (ALLOW_DIRTY=1 overrides, for a dry run only).
RELEASE_IDENTITY ?= Developer ID Application: S.A.P. SH.P.K. (MT2QHQX6PS)
RELEASE_TEAM_ID  ?= MT2QHQX6PS
NOTARY_PROFILE   ?= grantd-notary
NOTARIZE_ZIP     := dist/grantd-notarize.zip
DMG              := dist/grantd-$(VERSION).dmg
DMG_STAGE        := dist/dmg-stage

.PHONY: build helper helper-universal app icons bundle sign-bundle sign-release notarize dmg release release-check verify-release app-test ci-app app-dev-daemon dist-src sign test vet lint cover dev-test tools-check ci clean

build: ## Build bin/grantd (production tags: no dev backends)
	@echo "version: $(VERSION) ($(VERSION_SRC))"
	@# go build refuses to overwrite a fat (lipo) bin/grantd left by helper-universal
	@rm -f bin/grantd
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd ./cmd/grantd

dist-src: ## Export HEAD to dist/grantd-src.tar.gz with a VERSION file, so builds from the export carry the hash
	@v=$$(git describe --tags --always 2>/dev/null) || { echo "make dist-src: needs a git checkout" >&2; exit 1; }; \
	rm -rf dist/src-stage && mkdir -p dist/src-stage/grantd && \
	git archive HEAD | tar -x -C dist/src-stage/grantd && \
	echo "$$v" > dist/src-stage/grantd/VERSION && \
	tar -czf dist/grantd-src.tar.gz -C dist/src-stage grantd && \
	rm -rf dist/src-stage && \
	echo "wrote dist/grantd-src.tar.gz (VERSION $$v)"

sign: build ## Ad-hoc codesign bin/grantd with build/grantd.entitlements (macOS; see docs/MANUAL-TEST-MACOS.md 2a)
	codesign --force --sign - --identifier dev.grantd.grantd --entitlements build/grantd.entitlements bin/grantd
	codesign -d --entitlements - bin/grantd

helper: ## Build bin/grantd for macOS $(MIN_MACOS) (macOS only; asserts LC_BUILD_VERSION minos)
	@[ "$$(uname -s)" = Darwin ] || { echo "make helper: macOS only" >&2; exit 2; }
	@echo "version: $(VERSION) ($(VERSION_SRC)), minimum macOS $(MIN_MACOS)"
	@rm -f bin/grantd
	$(HELPER_ENV) $(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd ./cmd/grantd
	@minos=$$(otool -l bin/grantd | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	if [ "$$minos" != "$(MIN_MACOS)" ]; then echo "make helper: bin/grantd has minos '$$minos', want $(MIN_MACOS)" >&2; exit 1; fi; \
	echo "bin/grantd: minos $$minos"

helper-universal: ## Build a fat bin/grantd (arm64 + x86_64, cgo cross-built, lipo) for macOS $(MIN_MACOS)
	@[ "$$(uname -s)" = Darwin ] || { echo "make helper-universal: macOS only" >&2; exit 2; }
	@echo "version: $(VERSION) ($(VERSION_SRC)), minimum macOS $(MIN_MACOS), arm64 + x86_64"
	@set -e; sdk=$$(xcrun --sdk macosx --show-sdk-path); mkdir -p bin; rm -f bin/grantd bin/grantd-arm64 bin/grantd-amd64; \
	for pair in arm64:arm64 amd64:x86_64; do \
	  goarch=$${pair%%:*}; carch=$${pair##*:}; \
	  echo "go build GOARCH=$$goarch (clang -arch $$carch)"; \
	  GOOS=darwin GOARCH=$$goarch CGO_ENABLED=1 SDKROOT=$$sdk MACOSX_DEPLOYMENT_TARGET=$(MIN_MACOS) \
	    CC="clang -arch $$carch" CGO_CFLAGS=-mmacosx-version-min=$(MIN_MACOS) CGO_LDFLAGS=-mmacosx-version-min=$(MIN_MACOS) \
	    $(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd-$$goarch ./cmd/grantd; \
	  minos=$$(otool -l bin/grantd-$$goarch | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	  [ "$$minos" = "$(MIN_MACOS)" ] || { echo "make helper-universal: bin/grantd-$$goarch has minos '$$minos', want $(MIN_MACOS)" >&2; exit 1; }; \
	done; \
	lipo -create -output bin/grantd bin/grantd-arm64 bin/grantd-amd64; \
	rm -f bin/grantd-arm64 bin/grantd-amd64; \
	echo "bin/grantd: $$(lipo -archs bin/grantd), minos $(MIN_MACOS) in each slice"

app: $(HELPER_DEP) ## Build dist/grantd.app (unsigned) with xcodebuild: SwiftUI app + nested Go helper (macOS, Xcode); UNIVERSAL=1 for arm64 + x86_64
	@command -v xcodebuild >/dev/null || { echo "make app: xcodebuild not found (install Xcode, then xcode-select it)" >&2; exit 2; }
	rm -rf build/xcode/Build/Products
	xcodebuild -project app/Grantd.xcodeproj -scheme Grantd -configuration Release \
	  -derivedDataPath build/xcode CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO ARCHS="$(APP_ARCHS)" \
	  MACOSX_DEPLOYMENT_TARGET=$(MIN_MACOS) MARKETING_VERSION='$(VERSION)' CURRENT_PROJECT_VERSION=$(BUILD_NUMBER) \
	  PRODUCT_BUNDLE_IDENTIFIER=$(BUNDLE_ID) DAEMON_BUNDLE_ID=$(BUNDLE_ID).daemon DAEMON_MIN_MACOS=$(MIN_MACOS) \
	  build
	rm -rf $(APP)
	mkdir -p dist
	ditto $(APP_PRODUCT) $(APP)

bundle: app ## Assemble and check dist/grantd.app (unsigned; macOS; see docs/MANUAL-TEST-MACOS.md 2c)
	@echo "bundle version: $(VERSION) ($(VERSION_SRC))"
	@test -x $(APP)/Contents/MacOS/grantd-app || { echo "make bundle: $(APP)/Contents/MacOS/grantd-app missing"; exit 1; }
	@test -x $(HELPER_APP)/Contents/MacOS/grantd || { echo "make bundle: $(HELPER_APP)/Contents/MacOS/grantd missing"; exit 1; }
	plutil -lint $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist
	@for p in $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist; do \
	  v=$$(plutil -extract LSMinimumSystemVersion raw -o - $$p); \
	  [ "$$v" = "$(MIN_MACOS)" ] || { echo "make bundle: $$p LSMinimumSystemVersion is '$$v', want $(MIN_MACOS)" >&2; exit 1; }; \
	done
	@for p in $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist; do \
	  v=$$(plutil -extract CFBundleShortVersionString raw -o - $$p); b=$$(plutil -extract CFBundleVersion raw -o - $$p); \
	  [ "$$v" = "$(VERSION)" ] && [ "$$b" = "$(BUILD_NUMBER)" ] || { echo "make bundle: $$p has version '$$v' build '$$b', want '$(VERSION)' '$(BUILD_NUMBER)'" >&2; exit 1; }; \
	done
	@minos=$$(otool -l $(HELPER_APP)/Contents/MacOS/grantd | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	[ "$$minos" = "$(MIN_MACOS)" ] || { echo "make bundle: helper binary minos is '$$minos', want $(MIN_MACOS)" >&2; exit 1; }
	@if [ -n "$(EXPECT_ARCHS)" ]; then build/release/check-archs.sh "$(EXPECT_ARCHS)" $(APP)/Contents/MacOS/grantd-app $(HELPER_APP)/Contents/MacOS/grantd; fi
	@echo "built $(APP) (unsigned; run make sign-bundle to sign it, see docs/MANUAL-TEST-MACOS.md 2c)"

sign-bundle: ## Sign dist/grantd.app inside-out: make sign-bundle IDENTITY="Developer ID Application: Name (TEAMID)" PROFILE=/path/x.provisionprofile TEAM_ID=TEAMID
	@missing=""; \
	[ -n "$(IDENTITY)" ] || missing="$$missing IDENTITY"; \
	[ -n "$(PROFILE)" ]  || missing="$$missing PROFILE"; \
	[ -n "$(TEAM_ID)" ]  || missing="$$missing TEAM_ID"; \
	if [ -n "$$missing" ]; then \
	  echo "make sign-bundle: missing:$$missing" >&2; \
	  echo "usage: make bundle && make sign-bundle IDENTITY=\"Developer ID Application: Your Name (TEAMID)\" PROFILE=/path/to.provisionprofile TEAM_ID=TEAMID" >&2; \
	  echo "  IDENTITY: a signing certificate in your keychain (security find-identity -v -p codesigning), or its SHA-1 hash" >&2; \
	  echo "  PROFILE:  the provisioning profile for App ID $(BUNDLE_ID) with keychain-access-groups, downloaded from the developer portal" >&2; \
	  echo "  TEAM_ID:  your 10-character Team ID (developer portal, Membership details)" >&2; \
	  echo "see docs/MANUAL-TEST-MACOS.md section 2c" >&2; \
	  exit 2; \
	fi; \
	if [ "$(IDENTITY)" = "-" ]; then echo "make sign-bundle: IDENTITY=- (ad-hoc) cannot carry keychain-access-groups; the process would be killed at launch" >&2; exit 2; fi; \
	if ! echo "$(TEAM_ID)" | grep -Eq '^[A-Z0-9]{10}$$'; then echo "make sign-bundle: TEAM_ID '$(TEAM_ID)' does not look like a 10-character Team ID" >&2; exit 2; fi; \
	[ -f "$(PROFILE)" ] || { echo "make sign-bundle: PROFILE '$(PROFILE)' is not a file" >&2; exit 2; }; \
	[ -x $(APP)/Contents/MacOS/grantd-app ] || { echo "make sign-bundle: $(APP) not found; run make bundle first" >&2; exit 2; }; \
	[ -x $(HELPER_APP)/Contents/MacOS/grantd ] || { echo "make sign-bundle: $(HELPER_APP) not found; run make bundle first" >&2; exit 2; }
	cp "$(PROFILE)" $(APP)/Contents/embedded.provisionprofile
	cp "$(PROFILE)" $(HELPER_APP)/Contents/embedded.provisionprofile
	@# codesign does not expand $$(TeamIdentifierPrefix) (an Xcode build setting), so expand it here
	@# and drop the template comment. The expanded file is a build product in dist/.
	sed -e '/<!--/,/-->/d' \
	    -e 's|\$$(TeamIdentifierPrefix)|$(TEAM_ID).|g' \
	    -e 's|@BUNDLE_ID@|$(BUNDLE_ID)|g' -e 's|@KEYCHAIN_GROUP@|$(KEYCHAIN_GROUP)|g' \
	    build/bundle/grantd-app.entitlements > dist/grantd-app.entitlements
	plutil -lint dist/grantd-app.entitlements
	@# Inside out, no --deep: the helper first, then the outer app, whose seal records the signed helper.
	@# Signing a .app also signs its main executable (the Go binary, grantd-app), so these two
	@# calls cover all four Mach-O steps; build/release/verify-signing.sh fails if the tree ever
	@# holds a third Mach-O.
	@# Hardened runtime (--options runtime) is on for both with NO exception entitlements. Both
	@# bundles share one entitlements file, and it holds only the two profile-backed keys:
	@#  - com.apple.application-identifier, keychain-access-groups: the Secure Enclave key depends on
	@#    them (docs/MANUAL-TEST-MACOS.md 2c). Not hardened-runtime exceptions.
	@#  - allow-jit, allow-unsigned-executable-memory: not needed. Go emits no code at run time
	@#    (static binary text, no MAP_JIT or PROT_EXEC mappings in cmd/ or internal/); SwiftUI/AppKit
	@#    do not either.
	@#  - disable-library-validation: not needed. otool -L shows only /System and /usr/lib libraries
	@#    for both binaries, and neither dlopens anything (no dlopen in cmd/, internal/, app/).
	@#  - allow-dyld-environment-variables: not needed. Nothing here relies on DYLD_*.
	@#  - automation.apple-events: not needed. The daemon's approval dialog runs /usr/bin/osascript
	@#    as a child (display dialog, no events sent to another app); the child is Apple's, and it
	@#    does not inherit this process's hardened-runtime status.
	@# Add one only when a verification shows the signed bundle failing without it, with a comment here.
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantd-app.entitlements $(HELPER_APP)
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantd-app.entitlements $(APP)
	codesign --verify --deep --strict --verbose=2 $(APP)
	codesign -d --entitlements - $(APP)
	codesign -d --entitlements - $(HELPER_APP)
	@echo
	@echo "signed and verified: $(APP)"
	@echo "check that the entitlements above show $(TEAM_ID).$(BUNDLE_ID) and $(TEAM_ID).$(KEYCHAIN_GROUP), then:"
	@echo "  GRANTD_HOME=\$$(mktemp -d) $(HELPER_APP)/Contents/MacOS/grantd init     # must print: keystore tier: hardware"

sign-release: ## Developer ID, hardened-runtime signing of dist/grantd.app: make sign-release PROFILE=/path/Developer_ID.provisionprofile
	@[ -n "$(PROFILE)" ] || { echo "make sign-release: PROFILE is required" >&2; echo "usage: make sign-release PROFILE=/path/to/Developer_ID.provisionprofile   (after make bundle; see docs/RELEASE.md)" >&2; exit 2; }
	@[ "$(CODESIGN_TIMESTAMP)" = "--timestamp" ] || { echo "make sign-release: CODESIGN_TIMESTAMP is '$(CODESIGN_TIMESTAMP)'; a release needs a secure timestamp (--timestamp)" >&2; exit 2; }
	@security find-identity -v -p codesigning | grep -qF '"$(RELEASE_IDENTITY)"' || { echo "make sign-release: identity '$(RELEASE_IDENTITY)' not found in the keychain (security find-identity -v -p codesigning)" >&2; exit 2; }
	build/release/check-profile.sh "$(PROFILE)" $(RELEASE_TEAM_ID) $(BUNDLE_ID) $(KEYCHAIN_GROUP)
	$(MAKE) sign-bundle IDENTITY="$(RELEASE_IDENTITY)" TEAM_ID=$(RELEASE_TEAM_ID) PROFILE="$(PROFILE)"
	build/release/verify-signing.sh $(APP) $(HELPER_APP) $(RELEASE_TEAM_ID) $(if $(filter 1,$(RELEASE_UNIVERSAL)),"x86_64 arm64")

notarize: ## Notarize dist/grantd.app and staple the ticket (after sign-release): make notarize [NOTARY_PROFILE=grantd-notary]
	@command -v xcrun >/dev/null || { echo "make notarize: xcrun not found (install Xcode)" >&2; exit 2; }
	@codesign --verify --deep --strict $(APP) 2>/dev/null && codesign -dv $(APP) 2>&1 | grep -q 'runtime' || { echo "make notarize: $(APP) is missing or not signed with the hardened runtime; run make sign-release first" >&2; exit 2; }
	rm -f $(NOTARIZE_ZIP)
	ditto -c -k --keepParent $(APP) $(NOTARIZE_ZIP)
	build/release/notarize.sh $(NOTARIZE_ZIP) $(NOTARY_PROFILE)
	xcrun stapler staple $(APP)
	xcrun stapler validate $(APP)
	@# stapling adds the ticket outside the code seal; confirm the signature still verifies
	codesign --verify --deep --strict --verbose=2 $(APP)
	rm -f $(NOTARIZE_ZIP)

dmg: ## Build, sign, notarize and staple dist/grantd-$(VERSION).dmg from the stapled app (after notarize)
	@case "$(VERSION)" in *[!A-Za-z0-9._-]*) echo "make dmg: VERSION '$(VERSION)' has characters that do not belong in a file name" >&2; exit 2;; esac
	@case "$(VERSION)" in *-dirty) [ "$(ALLOW_DIRTY)" = 1 ] || { echo "make dmg: VERSION '$(VERSION)' is a dirty tree; commit first (ALLOW_DIRTY=1 for a dry run)" >&2; exit 2; };; esac
	@xcrun stapler validate $(APP) >/dev/null 2>&1 || { echo "make dmg: $(APP) is not notarized and stapled; run make notarize first" >&2; exit 2; }
	rm -rf $(DMG_STAGE) $(DMG)
	mkdir -p $(DMG_STAGE)
	ditto $(APP) $(DMG_STAGE)/grantd.app
	ln -s /Applications $(DMG_STAGE)/Applications
	cp build/release/dmg/DS_Store $(DMG_STAGE)/.DS_Store
	hdiutil create -volname grantd -srcfolder $(DMG_STAGE) -fs HFS+ -format UDZO -ov $(DMG)
	rm -rf $(DMG_STAGE)
	codesign --force --sign "$(RELEASE_IDENTITY)" --timestamp $(DMG)
	codesign --verify --verbose=2 $(DMG)
	@# The DMG is notarized too (after the app, so it contains the stapled app) so that it can be
	@# stapled and opens without a network round trip.
	build/release/notarize.sh $(DMG) $(NOTARY_PROFILE)
	xcrun stapler staple $(DMG)
	xcrun stapler validate $(DMG)
	@echo "built $(DMG)"

release-check: ## Preflight for make release: PROFILE, identity, version, notary credentials (no submission)
	@[ -n "$(PROFILE)" ] || { echo "make release: PROFILE is required" >&2; echo "usage: make release PROFILE=/path/to/Developer_ID.provisionprofile [NOTARY_PROFILE=grantd-notary]   (see docs/RELEASE.md)" >&2; exit 2; }
	@[ -f "$(PROFILE)" ] || { echo "make release: PROFILE '$(PROFILE)' is not a file" >&2; exit 2; }
	@security find-identity -v -p codesigning | grep -qF '"$(RELEASE_IDENTITY)"' || { echo "make release: identity '$(RELEASE_IDENTITY)' not found in the keychain" >&2; exit 2; }
	@case "$(VERSION)" in *-dirty) [ "$(ALLOW_DIRTY)" = 1 ] || { echo "make release: VERSION '$(VERSION)' is a dirty tree; commit first (ALLOW_DIRTY=1 for a dry run)" >&2; exit 2; };; esac
	build/release/check-profile.sh "$(PROFILE)" $(RELEASE_TEAM_ID) $(BUNDLE_ID) $(KEYCHAIN_GROUP)
	@# a read-only call that fails fast when the stored credentials are missing or wrong
	@xcrun notarytool history --keychain-profile $(NOTARY_PROFILE) >/dev/null || { echo "make release: no working notarytool credentials in keychain profile '$(NOTARY_PROFILE)'; see docs/RELEASE.md (one-time notary setup)" >&2; exit 2; }

verify-release: ## Gatekeeper assessment of dist/grantd.app and the DMG, the final check of make release
	@if [ "$(RELEASE_UNIVERSAL)" = 1 ]; then build/release/check-archs.sh "x86_64 arm64" $(APP)/Contents/MacOS/grantd-app $(HELPER_APP)/Contents/MacOS/grantd; fi
	xcrun stapler validate $(APP)
	xcrun stapler validate $(DMG)
	spctl -a -vv -t install $(APP)
	spctl -a -vv -t exec $(APP)
	spctl -a -vv -t open --context context:primary-signature $(DMG)
	@echo "release verified: $(DMG)"

release: ## Notarized, stapled DMG: make release PROFILE=/path/Developer_ID.provisionprofile (universal bundle, sign-release, notarize, dmg, verify)
	$(MAKE) release-check
	$(MAKE) bundle UNIVERSAL=$(RELEASE_UNIVERSAL)
	$(MAKE) sign-release UNIVERSAL=$(RELEASE_UNIVERSAL)
	$(MAKE) notarize
	$(MAKE) dmg
	$(MAKE) verify-release UNIVERSAL=$(RELEASE_UNIVERSAL)

app-test: ## Swift unit tests for app/GrantdKit against the Go dev daemon (INSECURE test backends; no signing needed)
	$(GO) build -tags $(DEV_TAG) -o build/grantd-dev ./cmd/grantd
	GRANTD_DEV_BIN=$(CURDIR)/build/grantd-dev swift test --package-path app/GrantdKit

ci-app: app app-test ## What the app needs on a macOS runner with Xcode: unsigned app build plus the Swift tests (not part of `make ci`)

app-dev-daemon: ## Run the INSECURE dev daemon on /tmp/gd-dev/s.sock for UI work (set GRANTD_SOCKET to it; never real secrets)
	$(GO) build -tags $(DEV_TAG) -o build/grantd-dev ./cmd/grantd
	mkdir -p /tmp/gd-dev && chmod 700 /tmp/gd-dev
	@[ -f /tmp/gd-dev/vault/vault.db ] || GRANTD_HOME=/tmp/gd-dev build/grantd-dev init
	GRANTD_HOME=/tmp/gd-dev GRANTD_DEV_APPROVE=allow build/grantd-dev daemon --socket /tmp/gd-dev/s.sock

test: ## Unit tests with the race detector
	$(GO) test -race ./...

vet: ## go vet, with and without the dev tag
	$(GO) vet ./...
	$(GO) vet -tags $(DEV_TAG) ./...

lint: ## staticcheck, with and without the dev tag
	$(STATICCHECK) ./...
	$(STATICCHECK) -tags $(DEV_TAG) ./...

cover: ## Print coverage (enforces nothing yet)
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

dev-test: ## Tests including the TierNone dev backends (INSECURE, test-only)
	$(GO) test -race -tags $(DEV_TAG) ./...

tools-check: ## Ensure pinned deps in internal/tools still compile
	$(GO) build -tags tools ./internal/tools/

ci: build vet lint test dev-test cover tools-check ## Everything CI runs

clean:
	rm -rf bin dist coverage.out build/xcode build/grantd-dev app/GrantdKit/.build

icons: ## Regenerate app/Grantd/Assets.xcassets/AppIcon.appiconset from build/icon/grantd-app-icon.png (macOS icon grid, transparent margin)
	swift build/icon/make-iconset.swift build/icon/grantd-app-icon.png app/Grantd/Assets.xcassets/AppIcon.appiconset
