# grantd Makefile. `make ci` is exactly what CI runs.
GO        ?= go
STATICCHECK ?= staticcheck
DEV_TAG   := grantd_dev
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -X main.version=$(VERSION)

# Signed .app bundle (roadmap 4a; docs/MANUAL-TEST-MACOS.md 2c). BUNDLE_ID is the
# single place the bundle identifier lives; it must match the App ID in the
# developer portal. KEYCHAIN_GROUP is the keychain access group, without the
# team prefix. Neither is part of `make ci`.
BUNDLE_ID      ?= dev.grantd.app
KEYCHAIN_GROUP ?= dev.grantd
APP            := dist/grantd.app
BUILD_NUMBER   ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 1)

.PHONY: build sign bundle sign-bundle test vet lint cover dev-test tools-check ci clean

build: ## Build bin/grantd (production tags: no dev backends)
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd ./cmd/grantd

sign: build ## Ad-hoc codesign bin/grantd with build/grantd.entitlements (macOS; see docs/MANUAL-TEST-MACOS.md 2a)
	codesign --force --sign - --identifier dev.grantd.grantd --entitlements build/grantd.entitlements bin/grantd
	codesign -d --entitlements - bin/grantd

bundle: build ## Assemble dist/grantd.app from bin/grantd (unsigned; macOS; see docs/MANUAL-TEST-MACOS.md 2c)
	@test -x bin/grantd || { echo "bin/grantd missing"; exit 1; }
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp bin/grantd $(APP)/Contents/MacOS/grantd
	@min="$(MIN_MACOS)"; \
	if [ -z "$$min" ]; then \
	  min=$$(otool -l bin/grantd 2>/dev/null | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $$2; exit}'); \
	fi; \
	min=$${min:-13.0}; \
	sed -e '/<!--/,/-->/d' -e 's|@BUNDLE_ID@|$(BUNDLE_ID)|g' -e 's|@VERSION@|$(VERSION)|g' \
	    -e 's|@BUILD@|$(BUILD_NUMBER)|g' -e "s|@MIN_MACOS@|$$min|g" \
	    build/bundle/Info.plist > $(APP)/Contents/Info.plist
	plutil -lint $(APP)/Contents/Info.plist
	@echo "built $(APP) (unsigned; run make sign-bundle to sign it, see docs/MANUAL-TEST-MACOS.md 2c)"

sign-bundle: ## Developer ID sign dist/grantd.app: make sign-bundle IDENTITY="Developer ID Application: Name (TEAMID)" PROFILE=/path/x.provisionprofile TEAM_ID=TEAMID
	@missing=""; \
	[ -n "$(IDENTITY)" ] || missing="$$missing IDENTITY"; \
	[ -n "$(PROFILE)" ]  || missing="$$missing PROFILE"; \
	[ -n "$(TEAM_ID)" ]  || missing="$$missing TEAM_ID"; \
	if [ -n "$$missing" ]; then \
	  echo "make sign-bundle: missing:$$missing" >&2; \
	  echo "usage: make bundle && make sign-bundle IDENTITY=\"Developer ID Application: Your Name (TEAMID)\" PROFILE=/path/to.provisionprofile TEAM_ID=TEAMID" >&2; \
	  echo "  IDENTITY: a Developer ID Application certificate in your keychain (security find-identity -v -p codesigning)" >&2; \
	  echo "  PROFILE:  the provisioning profile for App ID $(BUNDLE_ID) with keychain-access-groups, downloaded from the developer portal" >&2; \
	  echo "  TEAM_ID:  your 10-character Team ID (developer portal, Membership details)" >&2; \
	  echo "see docs/MANUAL-TEST-MACOS.md section 2c" >&2; \
	  exit 2; \
	fi; \
	if [ "$(IDENTITY)" = "-" ]; then echo "make sign-bundle: IDENTITY=- (ad-hoc) cannot carry keychain-access-groups; the process would be killed at launch" >&2; exit 2; fi; \
	if ! echo "$(TEAM_ID)" | grep -Eq '^[A-Z0-9]{10}$$'; then echo "make sign-bundle: TEAM_ID '$(TEAM_ID)' does not look like a 10-character Team ID" >&2; exit 2; fi; \
	[ -f "$(PROFILE)" ] || { echo "make sign-bundle: PROFILE '$(PROFILE)' is not a file" >&2; exit 2; }; \
	[ -x $(APP)/Contents/MacOS/grantd ] || { echo "make sign-bundle: $(APP) not found; run make bundle first" >&2; exit 2; }
	cp "$(PROFILE)" $(APP)/Contents/embedded.provisionprofile
	@# codesign does not expand $$(TeamIdentifierPrefix) (an Xcode build setting), so expand it here
	@# and drop the template comment. The expanded file is a build product in dist/.
	sed -e '/<!--/,/-->/d' \
	    -e 's|\$$(TeamIdentifierPrefix)|$(TEAM_ID).|g' \
	    -e 's|@BUNDLE_ID@|$(BUNDLE_ID)|g' -e 's|@KEYCHAIN_GROUP@|$(KEYCHAIN_GROUP)|g' \
	    build/bundle/grantd-app.entitlements > dist/grantd-app.entitlements
	plutil -lint dist/grantd-app.entitlements
	codesign --force --options runtime --timestamp --sign "$(IDENTITY)" --entitlements dist/grantd-app.entitlements $(APP)
	codesign --verify --deep --strict --verbose=2 $(APP)
	codesign -d --entitlements - $(APP)
	@echo
	@echo "signed and verified: $(APP)"
	@echo "check that the entitlements above show $(TEAM_ID).$(BUNDLE_ID) and $(TEAM_ID).$(KEYCHAIN_GROUP), then:"
	@echo "  GRANTD_HOME=\$$(mktemp -d) $(APP)/Contents/MacOS/grantd init     # must print: keystore tier: hardware"

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
	rm -rf bin dist coverage.out
