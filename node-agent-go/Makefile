APP_NAME    := noo-node-agent
IMAGE_NAME  := noomesh/node-agent
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# main.version does not exist — the stamp lives in internal/version (the
# heartbeat app_version and `noo-node-agent --version` both read it).
VPKG        := github.com/noomesh/noomesh/node-agent-go/internal/version
LDFLAGS     := -s -w -X $(VPKG).Version=$(VERSION)
GOTOOLCHAIN := local

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	CGO_ENABLED=0 GOTOOLCHAIN=$(GOTOOLCHAIN) go build -ldflags "$(LDFLAGS)" \
		-o bin/$(APP_NAME) ./cmd/node-agent/

# ── noo-hostd ──
#
# A SECOND binary from this module, not a mode of the first. noo-node-agent
# listens on :8081 with mTLS; noo-hostd must have no network surface at all,
# because it runs on the controller — which holds the age key and the CA key —
# and it can restart containers and ALTER database roles. Two artifacts make
# "does it listen?" a fact about the code rather than a configuration promise
# on the most privileged machine in the fleet. They share internal packages;
# they do not share a process.

HOSTD_NAME := noo-hostd

.PHONY: build-hostd
build-hostd:
	CGO_ENABLED=0 GOTOOLCHAIN=$(GOTOOLCHAIN) go build -ldflags "$(LDFLAGS)" \
		-o bin/$(HOSTD_NAME) ./cmd/noo-hostd/

# Controllers are x86_64 Linux (incl. WSL2) or Apple Silicon today; arm64 Linux
# is here for the Pi-as-controller case rather than as a worker target.
.PHONY: build-hostd-all
build-hostd-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(HOSTD_NAME)-linux-amd64 ./cmd/noo-hostd/
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(HOSTD_NAME)-linux-arm64 ./cmd/noo-hostd/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(HOSTD_NAME)-darwin-arm64 ./cmd/noo-hostd/

# Cross-compile all deployment targets
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64

# Tier 1-3: GPU workers + CPU workers (x86_64 Linux)
.PHONY: build-linux-amd64
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME)-linux-amd64 ./cmd/node-agent/

# Tier 4-5: Edge (Jetson, RPi5, RK3588) + Companion (ARM64 Linux)
.PHONY: build-linux-arm64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME)-linux-arm64 ./cmd/node-agent/

# macOS nodes (heterogeneous placement — see docs/models/backends.md).
# The agent runs NATIVELY on macOS (not in Docker) so it can launch a native
# Metal backend (Ollama) — Docker-for-Mac can't pass the GPU through. Pure Go
# (CGO_ENABLED=0), so these cross-compile from any host. Kept out of the
# default `build-all` (the Linux fleet); build explicitly with `make build-mac`.
.PHONY: build-mac
build-mac: build-darwin-arm64 build-darwin-amd64

# Apple Silicon (M1/M2/M3/M4)
.PHONY: build-darwin-arm64
build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME)-darwin-arm64 ./cmd/node-agent/

# Intel Macs
.PHONY: build-darwin-amd64
build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GOTOOLCHAIN=$(GOTOOLCHAIN) \
		go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME)-darwin-amd64 ./cmd/node-agent/

# ── Docker ──

# Build Docker image for current platform
.PHONY: docker
docker:
	docker build -t $(IMAGE_NAME):latest \
		-f ../docker/Dockerfile.node-agent-go ..

# Build multi-arch Docker image (amd64 + arm64)
# Requires: docker buildx create --use
.PHONY: docker-multiarch
docker-multiarch:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE_NAME):latest \
		-t $(IMAGE_NAME):$(VERSION) \
		-f ../docker/Dockerfile.node-agent-go \
		--push ..

# Build multi-arch and load locally (single platform at a time)
.PHONY: docker-arm64
docker-arm64:
	docker buildx build \
		--platform linux/arm64 \
		-t $(IMAGE_NAME):arm64 \
		-f ../docker/Dockerfile.node-agent-go \
		--load ..

# ── Edge Deployment — RETIRED, the rail is the only lane ──

# `make deploy-edge` and scripts/deploy-edge.sh are gone: agents are delivered over the
# rail and never pushed by hand.
#
# The target is kept as a refusal rather than deleted, because muscle memory
# outlives a script and a bare "No rule to make target" teaches nothing.
.PHONY: deploy-edge
deploy-edge:
	@echo "make deploy-edge is retired — agents are delivered over the rail, never pushed by hand."
	@echo
	@echo "  Fresh node:    noo cluster bootstrap-token create --node <name>   (paste the one-liner ON the node)"
	@echo "                 noo cluster provision <name> --wait"
	@echo "  Upgrade:       noo cluster upgrade-agents [<node>...]"
	@echo
	@echo "The rail is digest-verified, health-checked, auto-reverting and uses no SSH."
	@echo "That last part is why this is gone: tag:controller -> tag:worker:22 is no longer"
	@echo "granted, so the old script would have HUNG from the controller rather than failed."
	@exit 1

# ── Quality ──

.PHONY: test
test:
	GOTOOLCHAIN=$(GOTOOLCHAIN) go test -v -race ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: vet
vet:
	GOTOOLCHAIN=$(GOTOOLCHAIN) go vet ./...

# ── Utilities ──

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: deps
deps:
	GOTOOLCHAIN=$(GOTOOLCHAIN) go mod tidy
	GOTOOLCHAIN=$(GOTOOLCHAIN) go mod download

# Show binary sizes for all platforms
.PHONY: size
size: build-all
	@echo ""
	@echo "Binary sizes:"
	@ls -lh bin/$(APP_NAME)-*
	@echo ""
	@echo "Docker image:"
	@docker images $(IMAGE_NAME) --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" 2>/dev/null || true
