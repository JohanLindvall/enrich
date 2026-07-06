.PHONY: all check test lint bench fix generate update-tools

GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin
PATH := $(GOBIN):$(PATH)
export PATH

all: fix check

# Lint + the full test suite.
check: lint test

test:
	go test -cover ./...

lint: $(GOBIN)/golangci-lint
	golangci-lint run ./...

# Run every benchmark without rendering anything — a quick smoke check.
bench:
	go test -run='^$$' -bench=. -benchmem .

# Regenerate fields_unmarshal.go from the field definitions in fields.go with
# the lightning JSON decoder generator.
generate:
	go run github.com/JohanLindvall/lightning fields.go

fix: generate
	gofmt -w .
	go mod tidy

update-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

$(GOBIN)/golangci-lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
