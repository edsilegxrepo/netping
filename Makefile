# ==================================================
# Constants & Multi-Platform Configuration
# ==================================================

# Meta
VERSION ?= $(shell cat version.txt 2>/dev/null || echo "dev")
MAINTAINER := https://github.com/edsilegxrepo
DESCRIPTION := Modern, multi-protocol network latency and diagnostics prober. Written in Go

VERSION_PACKAGE := github.com/edsilegx/netping/internal/config
GO_LDFLAGS := -ldflags "-s -w -X $(VERSION_PACKAGE).version=$(VERSION)"
GO_MAIN_PATH := ./cmd

# IO directories
TARGET_DIR := bin/target
OUTPUT_DIR := bin/output

# Platform Conditionals
ifeq ($(OS),Windows_NT)
	SHELL := bash
	BIN_NAME := netping.exe
else
	SHELL := /bin/bash
	BIN_NAME := netping
endif

# Release Artifacts
RELEASE_ARTIFACTS := \
	$(OUTPUT_DIR)/netping-linux-amd64-static.tar.gz \
	$(OUTPUT_DIR)/netping-linux-amd64-dynamic.tar.gz \
	$(OUTPUT_DIR)/netping-windows-amd64-static.zip \
	$(OUTPUT_DIR)/netping-windows-amd64-dynamic.zip \
	$(OUTPUT_DIR)/netping-amd64.deb

# ==================================================
# Phony Targets
# ==================================================

.PHONY: all build release check clean update format lint vet sec test tidyup

all: build

# Build for current platform
build: $(TARGET_DIR)/$(BIN_NAME)

# Build all release artifacts
release: $(RELEASE_ARTIFACTS)

check: format vet lint sec test

# Remove all build artifacts
clean:
	@rm -rf $(TARGET_DIR)/ $(OUTPUT_DIR)/

update:
	@echo "[+] Updating Go dependencies"
	@go get -u ./...
	@go mod tidy
	@echo "[+] Done"

format:
	@echo "[+] Formatting files recursively"
	@gofumpt -l -w -extra .

vet:
	@echo "[+] Running Go vet"
	@go vet ./...

lint:
	@echo "[+] Running golangci-lint"
	@golangci-lint run --no-config ./...

sec:
	@echo "[+] Running Gosec"
	@gosec ./...

test:
	@echo "[+] Running all unit and integration tests with race detector"
	@go test -tags=integration -count=1 -race ./...

tidyup:
	@echo "[+] Running go mod tidy"
	@go mod tidy

# ==================================================
# Raw Binaries
# ==================================================

$(TARGET_DIR)/:
	@mkdir -p $@

$(TARGET_DIR)/$(BIN_NAME): $(TARGET_DIR)/
	@echo "[+] Building binary for current platform: $@"
	@go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH)

$(TARGET_DIR)/%/:
	@mkdir -p $@

# Linux / Unix binaries
$(TARGET_DIR)/linux-%-static/netping: $(TARGET_DIR)/linux-%-static/
	@echo "[+] Building binary: $@"
	@GOOS=linux GOARCH=$* CGO_ENABLED=0 go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH)

$(TARGET_DIR)/linux-%-dynamic/netping: $(TARGET_DIR)/linux-%-dynamic/
	@echo "[+] Building binary: $@"
	@GOOS=linux GOARCH=$* CGO_ENABLED=1 go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH)

# Windows binaries
$(TARGET_DIR)/windows-%-static/netping.exe: $(TARGET_DIR)/windows-%-static/
	@echo "[+] Building binary: $@"
	@GOOS=windows GOARCH=$* CGO_ENABLED=0 go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH)

$(TARGET_DIR)/windows-%-dynamic/netping.exe: $(TARGET_DIR)/windows-%-dynamic/
	@echo "[+] Building binary: $@"
	@GOOS=windows GOARCH=$* CGO_ENABLED=1 go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH)

# ==================================================
# Release Outputs
# ==================================================

$(OUTPUT_DIR)/:
	@mkdir -p $@

# .tar.gz archive
$(OUTPUT_DIR)/netping-%.tar.gz: $(TARGET_DIR)/%/netping $(OUTPUT_DIR)/
	@echo "[+] Compressing binary: $@"
	@tar -C $$(dirname $<) -czvf $@ netping >/dev/null
	@sha256sum $@ | awk '{print $$2 ": " $$1}'

# .zip archive (Windows)
$(OUTPUT_DIR)/netping-windows-%.zip: $(TARGET_DIR)/windows-%/netping.exe $(OUTPUT_DIR)/
	@echo "[+] Compressing binary: $@"
	@zip -j $@ $< >/dev/null
	@sha256sum $@ | awk '{print $$2 ": " $$1}'

# .deb package (Linux)
$(OUTPUT_DIR)/netping-%.deb: $(TARGET_DIR)/linux-%-static/netping $(OUTPUT_DIR)/
	@if command -v dpkg-deb >/dev/null 2>&1; then \
		echo "[+] Creating debian package: $@"; \
		PKG_DIR=$$(mktemp -dt make-netping.XXXXX); \
		install -Dm 755 -t $$PKG_DIR/usr/bin/ $<; \
		mkdir $$PKG_DIR/DEBIAN; pushd $$PKG_DIR/DEBIAN >/dev/null; \
		echo "Package: netping" >>control; \
		echo "Version: $(VERSION)" >>control; \
		echo "Section: custom" >>control; \
		echo "Priority: optional" >>control; \
		echo "Architecture: $*" >>control; \
		echo "Essential: no" >>control; \
		echo "Maintainer: $(MAINTAINER)" >>control; \
		echo "Description: $(DESCRIPTION)" >>control; \
		popd >/dev/null; \
		dpkg-deb --build $$PKG_DIR $@; \
	else \
		echo "[-] Skipping debian package: dpkg-deb tool not available"; \
	fi
