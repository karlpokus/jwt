VERSION := $(shell git describe --tags --dirty --always)

.PHONY: test install

test:
	@go test

install:
	@go install -trimpath -ldflags '-s -w -X main.version=$(VERSION)' ./cmd/jwt
