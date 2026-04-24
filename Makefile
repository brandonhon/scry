# Makefile for scry. Run `make help` for a list of targets.

export GO111MODULE := on
# Pin the Go toolchain so `go get @latest` stops bumping go.mod's go
# directive to whatever's installed locally. Set GOTOOLCHAIN=local to
# override (e.g. when debugging with a newer toolchain).
export GOTOOLCHAIN ?= go1.24.4

BIN       ?= scry
PKG       := ./cmd/scry
OUT_DIR   ?= bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X github.com/bhoneycutt/scry/internal/cli.Version=$(VERSION)
GOFLAGS   ?=

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9._-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the scry binary for the host platform
	@mkdir -p $(OUT_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BIN) $(PKG)

.PHONY: install
install: ## Install scry into $$GOBIN
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(PKG)

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile to coverage.out
	go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Format all Go sources
	gofmt -s -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: ci
ci: vet test ## Targets run in CI

.PHONY: cross
cross: ## Cross-compile release binaries for linux/amd64 and windows/amd64
	@mkdir -p $(OUT_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BIN)-linux-amd64 $(PKG)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BIN)-windows-amd64.exe $(PKG)

.PHONY: man
man: ## Generate docs/man/scry.1
	go run ./cmd/gen-man docs/man

.PHONY: regen-data
regen-data: ## Regenerate top.go + service.go from data/iana-service-names-port-numbers.csv
	go run ./cmd/gen-top-ports -in data/iana-service-names-port-numbers.csv -out internal/portscan/top.go
	go run ./cmd/gen-services   -in data/iana-service-names-port-numbers.csv -out internal/output/service.go

.PHONY: fuzz
fuzz: ## Run parser fuzz targets for 30s each
	go test -fuzz=^FuzzParse$$ -fuzztime=30s -run=_ ./internal/target/...
	go test -fuzz=^FuzzParseExclude$$ -fuzztime=30s -run=_ ./internal/target/...
	go test -fuzz=^FuzzParseRange$$ -fuzztime=30s -run=_ ./internal/target/...

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(OUT_DIR) coverage.out coverage.html

.PHONY: run
run: ## Build and run against 127.0.0.1:22 (PORT=22 to override)
	$(MAKE) build
	./$(OUT_DIR)/$(BIN) 127.0.0.1 -p $${PORT:-22}
