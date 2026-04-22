.PHONY: build test lint scan clean

BINARY=shieldops
GOFLAGS=-ldflags="-s -w"

build:
	go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/scan/

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

scan: build
	./bin/$(BINARY) scan --kubeconfig ~/.kube/config

clean:
	rm -rf bin/
