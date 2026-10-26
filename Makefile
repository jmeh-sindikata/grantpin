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

.PHONY: build helper app icons bundle sign-bundle app-test ci-app app-dev-daemon dist-src sign test vet lint cover dev-test tools-check ci clean

build: ## Build bin/grantd (production tags: no dev backends)
	@echo "version: $(VERSION) ($(VERSION_SRC))"
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
	$(HELPER_ENV) $(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd ./cmd/grantd
	@minos=$$(otool -l bin/grantd | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	if [ "$$minos" != "$(MIN_MACOS)" ]; then echo "make helper: bin/grantd has minos '$$minos', want $(MIN_MACOS)" >&2; exit 1; fi; \
	echo "bin/grantd: minos $$minos"

app: helper ## Build dist/grantd.app (unsigned) with xcodebuild: SwiftUI app + nested Go helper (macOS, Xcode)
	@command -v xcodebuild >/dev/null || { echo "make app: xcodebuild not found (install Xcode, then xcode-select it)" >&2; exit 2; }
	rm -rf build/xcode/Build/Products
	xcodebuild -project app/Grantd.xcodeproj -scheme Grantd -configuration Release \
	  -derivedDataPath build/xcode CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO ARCHS=$$(uname -m) \
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
	@minos=$$(otool -l $(HELPER_APP)/Contents/MacOS/grantd | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	[ "$$minos" = "$(MIN_MACOS)" ] || { echo "make bundle: helper binary minos is '$$minos', want $(MIN_MACOS)" >&2; exit 1; }
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
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantd-app.entitlements $(HELPER_APP)
	codesign --force --options runtime $(CODESIGN_TIMESTAMP) --sign "$(IDENTITY)" --entitlements dist/grantd-app.entitlements $(APP)
	codesign --verify --deep --strict --verbose=2 $(APP)
	codesign -d --entitlements - $(APP)
	codesign -d --entitlements - $(HELPER_APP)
	@echo
	@echo "signed and verified: $(APP)"
	@echo "check that the entitlements above show $(TEAM_ID).$(BUNDLE_ID) and $(TEAM_ID).$(KEYCHAIN_GROUP), then:"
	@echo "  GRANTD_HOME=\$$(mktemp -d) $(HELPER_APP)/Contents/MacOS/grantd init     # must print: keystore tier: hardware"

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
