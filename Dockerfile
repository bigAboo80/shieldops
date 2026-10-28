# ShieldOps image: static Go binary + trivy on distroless, runs as non-root.
#
# BIN=prebuilt takes bin/shieldops built on the host (make image-private)
# instead of compiling in a golang image; BuildKit then skips the build stage.
ARG GO_VERSION=1.26
ARG TRIVY_VERSION=0.69.3
ARG BIN=build

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY pkg pkg
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shieldops ./cmd/shieldops

FROM scratch AS prebuilt
COPY bin/shieldops /out/shieldops

FROM ${BIN} AS bin

FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

# CI image (--target ci): the same binaries with the busybox shell that
# GitLab CI and Actions need to run job scripts.
FROM gcr.io/distroless/static-debian12:debug-nonroot AS ci
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=bin --chmod=0755 /out/shieldops /usr/local/bin/shieldops
USER 65532:65532
ENTRYPOINT []
CMD ["shieldops", "help"]

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
# Explicit mode: a host build under a strict umask would leave the binary
# unreadable for the non-root user of the image.
COPY --from=bin --chmod=0755 /out/shieldops /usr/local/bin/shieldops
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/shieldops"]
CMD ["help"]
