.PHONY: build test lint scan image clean

BINARY=shieldops
GOFLAGS=-trimpath -ldflags="-s -w"

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/shieldops/

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

scan: build
	./bin/$(BINARY) scan -output report.html

image:
	docker build -t shieldops:dev .

clean:
	rm -rf bin/
