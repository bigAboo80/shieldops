# ShieldOps

Agentless Kubernetes security scanner. Detects toxic privilege combinations, exposed secrets, and CVEs. Generates an HTML report with findings mapped to FSTEK controls.

No agents. No SaaS. No data leaves your cluster.

## What it detects

- **Privileged pods with internet exposure** — privileged or hostNetwork pods reachable from outside
- **Cluster-admin ServiceAccounts in running pods** — ServiceAccounts bound to cluster-admin running in production
- **Secrets in internet-exposed pods** — pods mounting secrets while exposed via LoadBalancer/NodePort

Each finding includes a full attack path: how an attacker could chain the issue into cluster compromise.

## How it works

```
kubectl → inventory → PostgreSQL graph → detectors → HTML report
```

ShieldOps reads your cluster via the Kubernetes API (read-only), builds a graph of relationships between pods, service accounts, roles, and services, then queries that graph for dangerous combinations.

CVE scanning is done via [Trivy](https://github.com/aquasecurity/trivy) against container images found in the cluster.

## Requirements

- Go 1.24+
- PostgreSQL (for the security graph)
- `kubectl` access to the cluster (read-only kubeconfig is enough)
- Trivy (for CVE scanning)

## Usage

```bash
# Build
make build

# Scan your cluster
./bin/shieldops scan --kubeconfig ~/.kube/config --db "postgres://user:pass@localhost/shieldops"

# Output: report.html in current directory
```

## Install

```bash
go install github.com/bigAboo80/shieldops/cmd/scan@latest
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
make lint     # golangci-lint run ./...
```

Local dev environment (PostgreSQL + test cluster) is in `infra/dev-env/`.

## Status

MVP — core scan pipeline works. FSTEK control mapping is in progress.

Feedback welcome: open an issue or write to [Habr](https://habr.com).
