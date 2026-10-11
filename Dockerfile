# ShieldOps image: static Go binary + trivy on distroless, runs as non-root.
ARG GO_VERSION=1.26
ARG TRIVY_VERSION=0.69.3

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY pkg pkg
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shieldops ./cmd/shieldops

FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/shieldops /usr/local/bin/shieldops
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/shieldops"]
CMD ["serve"]
