# ShieldOps

Agentless Kubernetes security scanner. Detects toxic privilege combinations, exposed secrets, and CVEs. Generates an HTML report with findings mapped to FSTEK controls, and tells you what changed since the previous scan.

This repository is the **open demo edition**: the one-shot `scan` CLI with the graph detectors and the HTML report.

No agents. No SaaS. No data leaves your cluster.

## What it detects

- **Cluster-admin ServiceAccounts in running workloads** — workloads whose ServiceAccount is bound to `cluster-admin`
- **Secrets in exposed workloads** — workloads mounting secrets (volumes, projected volumes, `envFrom`, `env`) while exposed via LoadBalancer/NodePort
- **Exposed workloads with known CVEs** — LoadBalancer/NodePort workloads running images with CRITICAL/HIGH CVEs

Each finding includes a full attack path: how an attacker could chain the issue into cluster compromise.

Findings are reported per workload (`Deployment/web`, `StatefulSet/db`, ...), not per pod: three replicas give one finding, and a finding keeps its identity across pod restarts and rollouts.

## How it works

```
Kubernetes API (read-only) → inventory → SQLite graph → detectors → report
```

ShieldOps reads your cluster via the Kubernetes API, builds a graph of relationships between pods, service accounts, roles, services and secrets, then queries that graph for dangerous combinations.

ShieldOps never reads Secrets — not even their metadata. RBAC cannot grant "metadata only", so a token allowed to list Secrets could read their values. Which Secrets a pod uses is taken from the pod spec.

Every scan is kept in a local SQLite database, so each report shows which findings are **new** and which were **resolved** since the previous successful scan. Comparison is careful: a scan run without Trivy does not report CVE findings as resolved.

CVE scanning is done via [Trivy](https://github.com/aquasecurity/trivy) against all container and init container images found in the cluster. Each image is scanned once; the vulnerability DB is updated once per scan.

## Run from your machine (CLI)

```bash
# Read-only scanner identity (once per cluster)
kubectl apply -f deploy/rbac.yaml
# Short-lived token for it, instead of a stored long-lived one
kubectl -n shieldops create token shieldops-scanner --duration=1h

make build
./bin/shieldops scan -kubeconfig ~/.kube/config -output report.html
```

`shieldops scan` flags:

| Flag | Default | Meaning |
|---|---|---|
| `-kubeconfig` | `$KUBECONFIG` or `~/.kube/config`; in-cluster if neither exists | kubeconfig path |
| `-context` | current | kubeconfig context |
| `-namespace` | all | namespace to scan |
| `-db` | `$SHIELDOPS_DB` or `shieldops.db` | SQLite database path |
| `-output` | none | HTML report path |
| `-keep-scans` | `100` | scans kept in the database |
| `-skip-trivy` | `false` | skip CVE scanning |
| `-trivy-cmd` | `trivy` | trivy command; may be wrapped, e.g. `"ssh scan-host trivy"` to pull images on a host with better bandwidth |
| `-trivy-cache` | trivy default | trivy cache directory |
| `-trivy-timeout` | `20m` | time budget for DB update and image scanning |

The CLI needs Trivy in `PATH` for CVE scanning. No database server is needed.

## Report

The HTML report lists all findings, with:
- Finding type and severity, `NEW` mark for findings that appeared since the previous scan
- Attack path description
- CVEs found in container images (top 3 by severity)
- Remediation recommendations
- Findings resolved since the previous scan
- FSTEK Order No.17 control table

## Architecture

```
cmd/shieldops/      CLI: scan
internal/
  connector/        Kubernetes API client (client-go)
  inventory/        Asset collection (pods, SAs, cluster role bindings, services)
  graph/            SQLite schema, per-scan graph storage, edge builder
  detectors/        Toxic combination detectors, scan comparison
  report/           HTML report (html/template)
pkg/trivy/          CVE scanning via Trivy
deploy/rbac.yaml    Read-only ServiceAccount for the scanner
```

## Development

```bash
make build    # compile
make test     # go test -race -count=1 ./...
make lint     # golangci-lint run ./...
make image    # docker build (runs `shieldops scan`)
```

End-to-end check on a test cluster: `test/e2e/fixtures.yaml` creates a deliberately vulnerable namespace that must produce exactly three findings (one per detector). Remove it with `kubectl delete -f test/e2e/fixtures.yaml`.

## Full product

The commercial edition runs inside the cluster as a virtual DevSecOps engineer: scheduled scans, a web interface with finding triage (accepted risk, false positive, fixed) that survives rescans, an audit log, SSO, Telegram / Mattermost notifications about new findings only, and a Helm chart. It is self-hosted and works in closed networks.

Feedback and pilots: open an issue or write to [Habr](https://habr.com/ru/articles/1039100/).
