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
	./bin/$(BINARY) --kubeconfig $${KUBECONFIG:-$$HOME/.kube/config} -output report.html

clean:
	rm -rf bin/
