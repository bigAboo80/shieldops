# ShieldOps

Agentless Kubernetes security scanner. Detects toxic privilege combinations, exposed secrets, and CVEs. Generates an HTML report with findings mapped to FSTEK controls.

No agents. No SaaS. No data leaves your cluster.

## What it detects

- **Cluster-admin ServiceAccounts in running pods** — pods whose ServiceAccount is bound to `cluster-admin`
- **Secrets in exposed pods** — pods mounting secrets (volumes, projected volumes, `envFrom`, `env`) while exposed via LoadBalancer/NodePort
- **Exposed pods with known CVEs** — LoadBalancer/NodePort pods running images with CRITICAL/HIGH CVEs

Each finding includes a full attack path: how an attacker could chain the issue into cluster compromise.

## How it works

```
kubectl → inventory → PostgreSQL graph → detectors → HTML report
```

ShieldOps reads your cluster via the Kubernetes API (read-only; Secrets are listed metadata-only, their values are never fetched), builds a graph of relationships between pods, service accounts, roles, and services, then queries that graph for dangerous combinations.

CVE scanning is done via [Trivy](https://github.com/aquasecurity/trivy) against all container and init container images found in the cluster. Each image is scanned once; the vulnerability DB is updated once per scan.

## Requirements

- Go 1.24+
- PostgreSQL (for the security graph)
- `kubectl` access to the cluster (read-only kubeconfig is enough)
- Trivy (for CVE scanning)

## Usage

```bash
# Read-only scanner identity (once per cluster)
kubectl apply -f deploy/rbac.yaml

# Build
make build

# Scan your cluster
export SHIELDOPS_DB="postgres://user:pass@localhost/shieldops?sslmode=disable"
./bin/shieldops -kubeconfig ~/.kube/config -output report.html
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | kubeconfig path |
| `-context` | current | kubeconfig context |
| `-namespace` | all | namespace to scan |
| `-db` | `$SHIELDOPS_DB` | PostgreSQL connection string |
| `-output` | none | HTML report path |
| `-skip-trivy` | `false` | skip CVE scanning |
| `-trivy-cmd` | `trivy` | trivy command; may be wrapped, e.g. `"ssh scan-host trivy"` to pull images on a host with better bandwidth |
| `-trivy-cache` | trivy default | trivy cache directory |
| `-trivy-timeout` | `20m` | time budget for DB update and image scanning |

Each scan replaces the graph with the current cluster state. The schema is created on first run.

## Install

```bash
go install github.com/bigAboo80/shieldops/cmd/scan@latest
# installs the binary as `scan` into $(go env GOPATH)/bin
```

## Report

The HTML report lists all findings grouped by pod, with:
- Finding type and severity
- Attack path description
- CVEs found in container images (top 3 by severity)
- Remediation recommendations

## Architecture

```
cmd/scan/           CLI entry point
internal/
  connector/        Kubernetes API client (client-go)
  inventory/        Asset collection (pods, SAs, roles, secrets, services)
  graph/            PostgreSQL schema + edge builder
  detectors/        Three toxic combination detectors
  report/           HTML report generator
pkg/trivy/          CVE scanning via Trivy
```

## Development

```bash
make build    # compile
make test     # go test -race -count=1 ./...
SHIELDOPS_TEST_DB=postgres://... make test   # + detector tests on a real PostgreSQL
make lint     # golangci-lint run ./...
```

Local dev environment is in `infra/dev-env/`.

End-to-end check on a test cluster: `test/e2e/fixtures.yaml` creates a deliberately vulnerable namespace that must produce exactly three findings (one per detector). Remove it with `kubectl delete -f test/e2e/fixtures.yaml`.

## Status

MVP — core scan pipeline works. FSTEK control mapping is in progress.

Feedback welcome: open an issue or write to [Habr](https://habr.com/ru/articles/1039100/).
