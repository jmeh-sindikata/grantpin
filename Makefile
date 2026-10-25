# grantd Makefile. `make ci` is exactly what CI runs.
GO        ?= go
STATICCHECK ?= staticcheck
DEV_TAG   := grantd_dev
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -X main.version=$(VERSION)

.PHONY: build sign test vet lint cover dev-test tools-check ci clean

build: ## Build bin/grantd (production tags: no dev backends)
	$(GO) build -ldflags '$(LDFLAGS)' -o bin/grantd ./cmd/grantd

sign: build ## Ad-hoc codesign bin/grantd with build/grantd.entitlements (macOS; see docs/MANUAL-TEST-MACOS.md 2a)
	codesign --force --sign - --identifier dev.grantd.grantd --entitlements build/grantd.entitlements bin/grantd
	codesign -d --entitlements - bin/grantd

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
	rm -rf bin coverage.out
