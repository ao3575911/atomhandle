.PHONY: all build test race vet fmt fmt-check fuzz e2e ci clean

BIN_DIR := bin
LDFLAGS := -s -w

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/atom ./cmd/atom
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/atom-log ./cmd/atom-log

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	test -z "$$(gofmt -l .)"

fuzz:
	go test ./internal/handle -fuzz=FuzzParseHandle -fuzztime=10s
	go test ./internal/doc -fuzz=FuzzParseDocument -fuzztime=10s
	go test ./internal/checkpoint -fuzz=FuzzParseCheckpoint -fuzztime=10s
	go test ./internal/merkle -fuzz=FuzzParseProof -fuzztime=10s

e2e: build
	./scripts/e2e.sh

ci: fmt-check vet race fuzz e2e

clean:
	rm -rf $(BIN_DIR) dist atom-data
