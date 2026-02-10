SHELL=/usr/bin/env bash
.SHELLFLAGS=-o pipefail -ec
.DEFAULT_GOAL := test

.PHONY: build
build:
	go build -o bagel ./cmd/bagel

test:
	go test ./... -cover

format:
	go fmt ./...

lint:
	golangci-lint run
