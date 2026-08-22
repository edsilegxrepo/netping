# ==================================================
# Constants
# ==================================================

# Meta
SHELL := /bin/bash
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
MAINTAINER := https://github.com/edsilegxrepo
DESCRIPTION := Modern, multi-protocol network latency and diagnostics prober. Written in Go

VERSION_PACKAGE := github.com/edsilegx/netping/internal/config
GO_LDFLAGS := -ldflags "-s -w -X $(VERSION_PACKAGE).version=$(VERSION)"
GO_MAIN_PATH := ./cmd/netping.go

# IO directories
TARGET_DIR := target
OUTPUT_DIR := output

# File lists
RELEASE_ARTIFACTS := \
	$(OUTPUT_DIR)/netping-linux-amd64-static.tar.gz \
	$(OUTPUT_DIR)/netping-linux-amd64-dynamic.tar.gz \
	$(OUTPUT_DIR)/netping-windows-amd64-static.zip \
	$(OUTPUT_DIR)/netping-windows-amd64-dynamic.zip \
	$(OUTPUT_DIR)/netping-amd64.deb

# Conditionals
ifeq ($(OS),Windows_NT)
BIN_NAME := netping.exe
else
BIN_NAME := netping
endif

# ==================================================
# Phony targets
# ==================================================

.PHONY: all build release clean update format vet test tidyup

all: build

# Build for current platform
build: $(TARGET_DIR)/$(BIN_NAME)

# Build all release artifacts
release: $(RELEASE_ARTIFACTS)

check: format vet test

# Remove all build artifacts
clean:
	rm -rf $(TARGET_DIR)/ $(OUTPUT_DIR)/

update:
	@echo "[+] Updating Go dependencies"
	@go get -u
	@echo "[+] Done"

format:
	@echo "[+] Formatting files"
	@gofmt -w *.go

vet:
	@echo "[+] Running Go vet"
	@go vet

test:
	@echo "[+] Running tests"
	@go test ./...

tidyup:
	@echo "[+] Running go mod tidy"
	@go get -u ./...
	@go mod tidy

# ==================================================
# Raw binaries
# ==================================================

# Output directory
.PRECIOUS: $(TARGET_DIR)/
$(TARGET_DIR)/:
	@mkdir -p $@

# Binary for current platform
.PRECIOUS: $(TARGET_DIR)/$(BIN_NAME)
$(TARGET_DIR)/$(BIN_NAME): $(TARGET_DIR)/
	@echo "[+] Building binary for current platform: $@"
	@go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH);

# Per-target output directory
.PRECIOUS: $(TARGET_DIR)/%/
$(TARGET_DIR)/%/:
	@mkdir -p $@

# Per-target netping binary
.PRECIOUS: $(TARGET_DIR)/%/netping
$(TARGET_DIR)/%/netping: $(TARGET_DIR)/%/
	@echo "[+] Building binary: $@"
	@export GOOS=$(word 1, $(subst -, ,$*)); \
	export GOARCH=$(word 2, $(subst -, ,$*)); \
	[ $(word 3, $(subst -, ,$*)) = static ] && export CGO_ENABLED=0; \
	go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH);

# Per-target netping.exe binary (Windows)
.PRECIOUS: $(TARGET_DIR)/windows-%/netping.exe
$(TARGET_DIR)/windows-%/netping.exe: $(TARGET_DIR)/windows-%/
	@echo "[+] Building binary: $@"
	@export GOOS=windows; \
	export GOARCH=$(word 1, $(subst -, ,$*)); \
	[ $(word 2, $(subst -, ,$*)) = static ] && export CGO_ENABLED=0; \
	go build $(GO_LDFLAGS) -o $@ $(GO_MAIN_PATH);

# ==================================================
# Release outputs
# ==================================================

# Output directory
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
	@echo "[+] Creating debian package: $@"
	@PKG_DIR=$$(mktemp -dt make-netping.XXXXX); \
	\
	install -Dm 755 -t $$PKG_DIR/usr/bin/ $<; \
	\
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
	\
	dpkg-deb --build $$PKG_DIR $@

# ==================================================
# Helpers
# ==================================================

# Force target
# See https://www.gnu.org/software/make/manual/html_node/Force-Targets.html
FORCE:
