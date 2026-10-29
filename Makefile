BINARY_NAME=possum
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-s -w -X github.com/possum-security/possum-core/pkg/version.Version=$(VERSION) \
              -X github.com/possum-security/possum-core/pkg/version.GitCommit=$(COMMIT) \
              -X github.com/possum-security/possum-core/pkg/version.BuildDate=$(BUILD_TIME)

.PHONY: all build clean test lint install

all: test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/possum

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

install: build
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)
