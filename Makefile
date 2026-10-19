.PHONY: build test lint scan image image-private clean publish

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

# Commercial edition image in the private registry, tagged with the commit.
# REGISTRY comes from the environment or the untracked local.mk
# (REGISTRY = <host>/<owner>); needs docker login with write:package.
-include local.mk
TAG ?= $(shell git rev-parse --short HEAD)
# The public image and Helm chart: version = appVersion of the chart. Needs
# docker login ghcr.io and helm registry login ghcr.io with write:packages.
PUBLIC_IMAGE ?= ghcr.io/bigaboo80/shieldops
PUBLIC_CHARTS ?= oci://ghcr.io/bigaboo80/charts
VERSION := $(shell sed -n 's/^appVersion: "\(.*\)"/\1/p' deploy/helm/shieldops/Chart.yaml)
image-private: build
	@test -n "$(REGISTRY)" || { echo "set REGISTRY in local.mk or the environment"; exit 1; }
	DOCKER_BUILDKIT=1 docker build --build-arg BIN=prebuilt -t $(REGISTRY)/shieldops:$(TAG) .
	docker push $(REGISTRY)/shieldops:$(TAG)

clean:
	rm -rf bin/

publish: build
	@test -z "$$(git status --porcelain)" || { echo "commit first: the image is built from HEAD"; exit 1; }
	DOCKER_BUILDKIT=1 docker build --build-arg BIN=prebuilt -t $(PUBLIC_IMAGE):$(VERSION) -t $(PUBLIC_IMAGE):latest .
	docker push $(PUBLIC_IMAGE):$(VERSION)
	docker push $(PUBLIC_IMAGE):latest
	rm -rf dist && mkdir -p dist && helm package deploy/helm/shieldops -d dist
	helm push dist/shieldops-$(VERSION).tgz $(PUBLIC_CHARTS)
