BINARY     := agentwarden
MODULE     := github.com/agentwarden/agentwarden
CMD        := ./cmd/agentwarden
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION)
BUILD_FLAGS:= -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build test lint vet cover clean run docker-build docker-up web-install web-dev

## all: build the binary (default target)
all: build

## build: compile a static binary to ./bin/agentwarden
build:
	@mkdir -p bin
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o bin/$(BINARY) $(CMD)
	@echo "✓  bin/$(BINARY) built (version=$(VERSION))"

## test: run the full test suite
test:
	go test ./... -count=1

## cover: run tests with coverage report
cover:
	go test ./... -coverprofile=coverage.txt -covermode=atomic
	go tool cover -html=coverage.txt -o coverage.html
	@echo "✓  coverage report: coverage.html"

## vet: run go vet
vet:
	go vet ./...

## lint: run golangci-lint (install separately: https://golangci-lint.run)
lint:
	golangci-lint run ./...

## run: start the server locally (hot-reload not included; use 'air' for that)
run: build
	WARDEN_CONFIG=./warden.yaml ./bin/$(BINARY)

## clean: remove build artifacts
clean:
	rm -rf bin/ coverage.txt coverage.html

## docker-build: build the Docker image
docker-build:
	docker build -t $(BINARY):$(VERSION) -t $(BINARY):latest .

## docker-up: start via docker-compose
docker-up:
	docker compose up --build

## web-install: install web dashboard dependencies
web-install:
	cd web && npm install

## web-dev: start the dashboard dev server (proxies /v1 to :8080)
web-dev: web-install
	cd web && npm run dev

## web-build: build the dashboard for production
web-build: web-install
	cd web && npm run build

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## //' | column -t -s ':'
