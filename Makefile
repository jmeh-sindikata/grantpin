# grantpin Makefile. `make ci` is exactly what CI runs.
GO        ?= go
STATICCHECK ?= staticcheck
DEV_TAG   := grantpin_dev
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

# Bundle and DMG version. VERSION (git describe) is reported verbatim by
# `grantpin --version` and `grantpin status`, but a tagged build must carry a plain
# X.Y.Z in the Info.plists. VERSION_NUM is X.Y.Z when VERSION is vX.Y.Z or X.Y.Z,
# optionally followed by git describe's -N-gHASH and -dirty suffixes; it is empty
# for an untagged build (a bare hash, "dev"). When set: CFBundleShortVersionString
# and CFBundleVersion are both X.Y.Z (Apple allows at most three numeric
# components in CFBundleVersion, so the -N commit count is not appended). When
# empty: the verbatim VERSION and the commit count, as before. DMG_VERSION is
# X.Y.Z only for a clean tag, so the DMG is grantpin-0.2.0.dmg; otherwise VERSION.
VERSION_NUM    := $(shell printf '%s' '$(VERSION)' | sed -nE 's/^v?([0-9]+\.[0-9]+\.[0-9]+)(-[0-9]+-g[0-9a-f]+)?(-dirty)?$$/\1/p')
DMG_VERSION    := $(shell printf '%s' '$(VERSION)' | sed -nE 's/^v?([0-9]+\.[0-9]+\.[0-9]+)$$/\1/p')
BUNDLE_VERSION := $(or $(VERSION_NUM),$(VERSION))

# Signed .app bundle (docs/UI-SPEC.md section 5; docs/MANUAL-TEST-MACOS.md 2c).
# The app is two bundles: the outer grantpin.app (SwiftUI menu-bar app, built by
# xcodebuild from app/) and, inside it, Contents/Helpers/grantpin-daemon.app
# whose main executable is the Go binary. BUNDLE_ID is the outer bundle's
# identifier and the single place it lives; it must match the App ID in the
# developer portal. The helper's is BUNDLE_ID.daemon. KEYCHAIN_GROUP is the
# keychain access group, without the team prefix. MIN_MACOS is the lowest macOS
# for both (the Go binary is built for it, see `make helper`). None of this is
# part of `make ci`; `make ci-app` is the app counterpart.
BUNDLE_ID      ?= dev.grantpin.app
KEYCHAIN_GROUP ?= dev.grantpin
MIN_MACOS      ?= 14.0
# Every directory that holds an unsigned or intermediate .app ends in .noindex, so
# Spotlight skips it: those copies share the installed app's bundle ID, and macOS
# may otherwise open the wrong one by bundle ID. `make clean-apps` deletes them.
BUILD_XCODE    := build/xcode.noindex
STAGE_DIR      := dist/stage.noindex
APP            := $(STAGE_DIR)/grantpin.app
HELPER_APP     := $(APP)/Contents/Helpers/grantpin-daemon.app
APP_PRODUCT    := $(BUILD_XCODE)/Build/Products/Release/grantpin-app.app
BUILD_NUMBER   ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 1)
BUNDLE_BUILD   := $(or $(VERSION_NUM),$(BUILD_NUMBER))
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
NOTARY_PROFILE   ?= grantpin-notary
NOTARIZE_ZIP     := dist/grantpin-notarize.zip
DMG              := dist/grantpin-$(or $(DMG_VERSION),$(VERSION)).dmg
DMG_STAGE        := $(STAGE_DIR)/dmg-stage

.PHONY: clean-apps build helper helper-universal app icons bundle sign-bundle sign-release notarize dmg release release-check verify-release app-test ci-app app-dev-daemon dist-src sign test vet lint cover dev-test tools-check ci clean

build: ## Build bin/grantpin (production tags: no dev backends)
	@echo "version: $(VERSION) ($(VERSION_SRC))"
	@# go build refuses to overwrite a fat (lipo) bin/grantpin left by helper-universal
	@rm -f bin/grantpin
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/grantpin ./cmd/grantpin

dist-src: ## Export HEAD to dist/grantpin-src.tar.gz with a VERSION file, so builds from the export carry the hash
	@v=$$(git describe --tags --always 2>/dev/null) || { echo "make dist-src: needs a git checkout" >&2; exit 1; }; \
	rm -rf dist/src-stage && mkdir -p dist/src-stage/grantpin && \
	git archive HEAD | tar -x -C dist/src-stage/grantpin && \
	echo "$$v" > dist/src-stage/grantpin/VERSION && \
	tar -czf dist/grantpin-src.tar.gz -C dist/src-stage grantpin && \
	rm -rf dist/src-stage && \
	echo "wrote dist/grantpin-src.tar.gz (VERSION $$v)"

sign: build ## Ad-hoc codesign bin/grantpin with build/grantpin.entitlements (macOS; see docs/MANUAL-TEST-MACOS.md 2a)
	codesign --force --sign - --identifier dev.grantpin.grantpin --entitlements build/grantpin.entitlements bin/grantpin
	codesign -d --entitlements - bin/grantpin

helper: ## Build bin/grantpin for macOS $(MIN_MACOS) (macOS only; asserts LC_BUILD_VERSION minos)
	@[ "$$(uname -s)" = Darwin ] || { echo "make helper: macOS only" >&2; exit 2; }
	@echo "version: $(VERSION) ($(VERSION_SRC)), minimum macOS $(MIN_MACOS)"
	@rm -f bin/grantpin
	$(HELPER_ENV) $(GO) build -ldflags '$(LDFLAGS)' -o bin/grantpin ./cmd/grantpin
	@minos=$$(otool -l bin/grantpin | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	if [ "$$minos" != "$(MIN_MACOS)" ]; then echo "make helper: bin/grantpin has minos '$$minos', want $(MIN_MACOS)" >&2; exit 1; fi; \
	echo "bin/grantpin: minos $$minos"

helper-universal: ## Build a fat bin/grantpin (arm64 + x86_64, cgo cross-built, lipo) for macOS $(MIN_MACOS)
	@[ "$$(uname -s)" = Darwin ] || { echo "make helper-universal: macOS only" >&2; exit 2; }
	@echo "version: $(VERSION) ($(VERSION_SRC)), minimum macOS $(MIN_MACOS), arm64 + x86_64"
	@set -e; sdk=$$(xcrun --sdk macosx --show-sdk-path); mkdir -p bin; rm -f bin/grantpin bin/grantpin-arm64 bin/grantpin-amd64; \
	for pair in arm64:arm64 amd64:x86_64; do \
	  goarch=$${pair%%:*}; carch=$${pair##*:}; \
	  echo "go build GOARCH=$$goarch (clang -arch $$carch)"; \
	  GOOS=darwin GOARCH=$$goarch CGO_ENABLED=1 SDKROOT=$$sdk MACOSX_DEPLOYMENT_TARGET=$(MIN_MACOS) \
	    CC="clang -arch $$carch" CGO_CFLAGS=-mmacosx-version-min=$(MIN_MACOS) CGO_LDFLAGS=-mmacosx-version-min=$(MIN_MACOS) \
	    $(GO) build -ldflags '$(LDFLAGS)' -o bin/grantpin-$$goarch ./cmd/grantpin; \
	  minos=$$(otool -l bin/grantpin-$$goarch | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	  [ "$$minos" = "$(MIN_MACOS)" ] || { echo "make helper-universal: bin/grantpin-$$goarch has minos '$$minos', want $(MIN_MACOS)" >&2; exit 1; }; \
	done; \
	lipo -create -output bin/grantpin bin/grantpin-arm64 bin/grantpin-amd64; \
	rm -f bin/grantpin-arm64 bin/grantpin-amd64; \
	echo "bin/grantpin: $$(lipo -archs bin/grantpin), minos $(MIN_MACOS) in each slice"

app: $(HELPER_DEP) ## Build dist/stage.noindex/grantpin.app (unsigned) with xcodebuild: SwiftUI app + nested Go helper (macOS, Xcode); UNIVERSAL=1 for arm64 + x86_64
	@command -v xcodebuild >/dev/null || { echo "make app: xcodebuild not found (install Xcode, then xcode-select it)" >&2; exit 2; }
	rm -rf $(BUILD_XCODE)/Build/Products
	xcodebuild -project app/Grantpin.xcodeproj -scheme Grantpin -configuration Release \
	  -derivedDataPath $(BUILD_XCODE) CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO ARCHS="$(APP_ARCHS)" \
	  MACOSX_DEPLOYMENT_TARGET=$(MIN_MACOS) MARKETING_VERSION='$(BUNDLE_VERSION)' CURRENT_PROJECT_VERSION=$(BUNDLE_BUILD) \
	  PRODUCT_BUNDLE_IDENTIFIER=$(BUNDLE_ID) DAEMON_BUNDLE_ID=$(BUNDLE_ID).daemon DAEMON_MIN_MACOS=$(MIN_MACOS) \
	  build
	rm -rf $(APP)
	mkdir -p $(STAGE_DIR)
	ditto $(APP_PRODUCT) $(APP)

bundle: app ## Assemble and check dist/stage.noindex/grantpin.app (unsigned; macOS; see docs/MANUAL-TEST-MACOS.md 2c)
	@echo "bundle version: $(VERSION) ($(VERSION_SRC)); CFBundleShortVersionString $(BUNDLE_VERSION), CFBundleVersion $(BUNDLE_BUILD)"
	@test -x $(APP)/Contents/MacOS/grantpin-app || { echo "make bundle: $(APP)/Contents/MacOS/grantpin-app missing"; exit 1; }
	@test -x $(HELPER_APP)/Contents/MacOS/grantpin || { echo "make bundle: $(HELPER_APP)/Contents/MacOS/grantpin missing"; exit 1; }
	plutil -lint $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist
	@for p in $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist; do \
	  v=$$(plutil -extract LSMinimumSystemVersion raw -o - $$p); \
	  [ "$$v" = "$(MIN_MACOS)" ] || { echo "make bundle: $$p LSMinimumSystemVersion is '$$v', want $(MIN_MACOS)" >&2; exit 1; }; \
	done
	@for p in $(APP)/Contents/Info.plist $(HELPER_APP)/Contents/Info.plist; do \
	  v=$$(plutil -extract CFBundleShortVersionString raw -o - $$p); b=$$(plutil -extract CFBundleVersion raw -o - $$p); \
	  [ "$$v" = "$(BUNDLE_VERSION)" ] && [ "$$b" = "$(BUNDLE_BUILD)" ] || { echo "make bundle: $$p has version '$$v' build '$$b', want '$(BUNDLE_VERSION)' '$(BUNDLE_BUILD)'" >&2; exit 1; }; \
	done
	@minos=$$(otool -l $(HELPER_APP)/Contents/MacOS/grantpin | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	[ "$$minos" = "$(MIN_MACOS)" ] || { echo "make bundle: helper binary minos is '$$minos', want $(MIN_MACOS)" >&2; exit 1; }
	@if [ -n "$(EXPECT_ARCHS)" ]; then build/release/check-archs.sh "$(EXPECT_ARCHS)" $(APP)/Contents/MacOS/grantpin-app $(HELPER_APP)/Contents/MacOS/grantpin; fi
	@echo "built $(APP) (unsigned; run make sign-bundle to sign it, see docs/MANUAL-TEST-MACOS.md 2c)"

sign-bundle: ## Sign dist/stage.noindex/grantpin.app inside-out: make sign-bundle IDENTITY="Developer ID Application: Name (TEAMID)" PROFILE=/path/x.provisionprofile TEAM_ID=TEAMID
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
	[ -x $(APP)/Contents/MacOS/grantpin-app ] || { echo "make sign-bundle: $(APP) not found; run make bundle first" >&2; exit 2; }; \
	[ -x $(HELPER_APP)/Contents/MacOS/grantpin ] || { echo "make sign-bundle: $(HELPER_APP) not found; run make bundle first" >&2; exit 2; }
	cp "$(PROFILE)" $(APP)/Contents/embedded.provisionprofile
	cp "$(PROFILE)" $(HELPER_APP)/Contents/embedded.provisionprofile
	@# codesign does not expand $$(TeamIdentifierPrefix) (an Xcode build setting), so expand it here
	@# and drop the template comment. The expanded file is a build product in dist/.
	sed -e '/<!--/,/-->/d' \
	    -e 's|\$$(TeamIdentifierPrefix)|$(TEAM_ID).|g' \
	    -e 's|@BUNDLE_ID@|$(BUNDLE_ID)|g' -e 's|@KEYCHAIN_GROUP@|$(KEYCHAIN_GROUP)|g' \
	    build/bundle/grantpin-app.entitlements > dist/grantpin-app.entitlements
	plutil -lint dist/grantpin-app.entitlements
	@# Inside out, no --deep: the helper first, then the outer app, whose seal records the signed helper.
	@# Signing a .app also signs its main executable (the Go binary, grantpin-app), so these two
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
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantpin-app.entitlements $(HELPER_APP)
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantpin-app.entitlements $(APP)
	codesign --verify --deep --strict --verbose=2 $(APP)
	codesign -d --entitlements - $(APP)
	codesign -d --entitlements - $(HELPER_APP)
	@echo
	@echo "signed and verified: $(APP)"
	@echo "check that the entitlements above show $(TEAM_ID).$(BUNDLE_ID) and $(TEAM_ID).$(KEYCHAIN_GROUP), then:"
	@echo "  GRANTPIN_HOME=\$$(mktemp -d) $(HELPER_APP)/Contents/MacOS/grantpin init     # must print: keystore tier: hardware"

sign-release: ## Developer ID, hardened-runtime signing of dist/stage.noindex/grantpin.app: make sign-release PROFILE=/path/Developer_ID.provisionprofile
	@[ -n "$(PROFILE)" ] || { echo "make sign-release: PROFILE is required" >&2; echo "usage: make sign-release PROFILE=/path/to/Developer_ID.provisionprofile   (after make bundle; see docs/RELEASE.md)" >&2; exit 2; }
	@[ "$(CODESIGN_TIMESTAMP)" = "--timestamp" ] || { echo "make sign-release: CODESIGN_TIMESTAMP is '$(CODESIGN_TIMESTAMP)'; a release needs a secure timestamp (--timestamp)" >&2; exit 2; }
	@security find-identity -v -p codesigning | grep -qF '"$(RELEASE_IDENTITY)"' || { echo "make sign-release: identity '$(RELEASE_IDENTITY)' not found in the keychain (security find-identity -v -p codesigning)" >&2; exit 2; }
	build/release/check-profile.sh "$(PROFILE)" $(RELEASE_TEAM_ID) $(BUNDLE_ID) $(KEYCHAIN_GROUP)
	$(MAKE) sign-bundle IDENTITY="$(RELEASE_IDENTITY)" TEAM_ID=$(RELEASE_TEAM_ID) PROFILE="$(PROFILE)"
	build/release/verify-signing.sh $(APP) $(HELPER_APP) $(RELEASE_TEAM_ID) $(if $(filter 1,$(RELEASE_UNIVERSAL)),"x86_64 arm64")

notarize: ## Notarize dist/stage.noindex/grantpin.app and staple the ticket (after sign-release): make notarize [NOTARY_PROFILE=grantpin-notary]
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

dmg: ## Build, sign, notarize and staple dist/grantpin-<version>.dmg (X.Y.Z for a clean vX.Y.Z tag) from the stapled app (after notarize)
	@case "$(VERSION)" in *[!A-Za-z0-9._-]*) echo "make dmg: VERSION '$(VERSION)' has characters that do not belong in a file name" >&2; exit 2;; esac
	@case "$(VERSION)" in *-dirty) [ "$(ALLOW_DIRTY)" = 1 ] || { echo "make dmg: VERSION '$(VERSION)' is a dirty tree; commit first (ALLOW_DIRTY=1 for a dry run)" >&2; exit 2; };; esac
	@xcrun stapler validate $(APP) >/dev/null 2>&1 || { echo "make dmg: $(APP) is not notarized and stapled; run make notarize first" >&2; exit 2; }
	rm -rf $(DMG_STAGE) $(DMG)
	mkdir -p $(DMG_STAGE)
	ditto $(APP) $(DMG_STAGE)/grantpin.app
	ln -s /Applications $(DMG_STAGE)/Applications
	cp build/release/dmg/DS_Store $(DMG_STAGE)/.DS_Store
	hdiutil create -volname grantpin -srcfolder $(DMG_STAGE) -fs HFS+ -format UDZO -ov $(DMG)
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
	@[ -n "$(PROFILE)" ] || { echo "make release: PROFILE is required" >&2; echo "usage: make release PROFILE=/path/to/Developer_ID.provisionprofile [NOTARY_PROFILE=grantpin-notary]   (see docs/RELEASE.md)" >&2; exit 2; }
	@[ -f "$(PROFILE)" ] || { echo "make release: PROFILE '$(PROFILE)' is not a file" >&2; exit 2; }
	@security find-identity -v -p codesigning | grep -qF '"$(RELEASE_IDENTITY)"' || { echo "make release: identity '$(RELEASE_IDENTITY)' not found in the keychain" >&2; exit 2; }
	@case "$(VERSION)" in *-dirty) [ "$(ALLOW_DIRTY)" = 1 ] || { echo "make release: VERSION '$(VERSION)' is a dirty tree; commit first (ALLOW_DIRTY=1 for a dry run)" >&2; exit 2; };; esac
	build/release/check-profile.sh "$(PROFILE)" $(RELEASE_TEAM_ID) $(BUNDLE_ID) $(KEYCHAIN_GROUP)
	@# a read-only call that fails fast when the stored credentials are missing or wrong
	@xcrun notarytool history --keychain-profile $(NOTARY_PROFILE) >/dev/null || { echo "make release: no working notarytool credentials in keychain profile '$(NOTARY_PROFILE)'; see docs/RELEASE.md (one-time notary setup)" >&2; exit 2; }

verify-release: ## Gatekeeper assessment of dist/stage.noindex/grantpin.app and the DMG, the final check of make release
	@if [ "$(RELEASE_UNIVERSAL)" = 1 ]; then build/release/check-archs.sh "x86_64 arm64" $(APP)/Contents/MacOS/grantpin-app $(HELPER_APP)/Contents/MacOS/grantpin; fi
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

app-test: ## Swift unit tests for app/GrantpinKit against the Go dev daemon (INSECURE test backends; no signing needed)
	$(GO) build -tags $(DEV_TAG) -o build/grantpin-dev ./cmd/grantpin
	GRANTPIN_DEV_BIN=$(CURDIR)/build/grantpin-dev swift test --package-path app/GrantpinKit

ci-app: app app-test ## What the app needs on a macOS runner with Xcode: unsigned app build plus the Swift tests (not part of `make ci`)

app-dev-daemon: ## Run the INSECURE dev daemon on /tmp/gd-dev/s.sock for UI work (set GRANTPIN_SOCKET to it; never real secrets)
	$(GO) build -tags $(DEV_TAG) -o build/grantpin-dev ./cmd/grantpin
	mkdir -p /tmp/gd-dev && chmod 700 /tmp/gd-dev
	@[ -f /tmp/gd-dev/vault/vault.db ] || GRANTPIN_HOME=/tmp/gd-dev build/grantpin-dev init
	GRANTPIN_HOME=/tmp/gd-dev GRANTPIN_DEV_APPROVE=allow build/grantpin-dev daemon --socket /tmp/gd-dev/s.sock

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
	rm -rf bin dist coverage.out $(BUILD_XCODE) build/xcode build/grantpin-dev app/GrantpinKit/.build

icons: ## Regenerate app/Grantpin/Assets.xcassets/AppIcon.appiconset from build/icon/grantpin-app-icon.png (macOS icon grid, transparent margin)
	swift build/icon/make-iconset.swift build/icon/grantpin-app-icon.png app/Grantpin/Assets.xcassets/AppIcon.appiconset

clean-apps: ## Delete the unsigned/intermediate app copies (everything under build/xcode.noindex and dist/stage.noindex, plus pre-.noindex leftovers); touches nothing outside the repo
	rm -rf $(BUILD_XCODE) $(STAGE_DIR) build/xcode dist/grantpin.app dist/dmg-stage
