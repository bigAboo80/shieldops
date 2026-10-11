# ShieldOps

Agentless Kubernetes security scanner. Detects toxic privilege combinations, exposed secrets, and CVEs. Generates an HTML report with findings mapped to FSTEK controls, and tells you what changed since the previous scan.

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

## Run in the cluster (Helm)

ShieldOps runs as a single pod: it scans on a schedule and serves the latest report.

```bash
helm install shieldops ./deploy/helm/shieldops --namespace shieldops --create-namespace

# open the latest report
kubectl -n shieldops port-forward deploy/shieldops 8080:8080
# → http://127.0.0.1:8080
```

The report is served on the pod's loopback interface only, so it is reachable through `kubectl port-forward` alone: access is controlled by Kubernetes RBAC, and nothing is exposed on the network.

Hardened by default:
- read-only ClusterRole without Secrets, short-lived projected ServiceAccount token
- distroless image, non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp
- NetworkPolicy: no ingress at all; egress only DNS and HTTPS (narrow `networkPolicy.egressCIDRs` to your API server and registries)
- database and report files are owner-only (`0600`)

Main values:

| Value | Default | Meaning |
|---|---|---|
| `scan.interval` | `6h` | time between scans |
| `scan.namespace` | all | namespace to scan |
| `trivy.enabled` | `true` | scan images for CVEs |
| `persistence.enabled` | `true` | keep scan history on a PVC (`5Gi`); without it history is lost on restart |
| `persistence.storageClass` | cluster default | storage class for the PVC |
| `image.digest` | none | pin the image by digest |

Images are published to `ghcr.io/bigaboo80/shieldops`, signed with cosign (keyless) and shipped with an SBOM and provenance attestation:

```bash
cosign verify ghcr.io/bigaboo80/shieldops:edge \
  --certificate-identity-regexp 'https://github.com/bigAboo80/shieldops/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Run from your machine (CLI)

```bash
# Read-only scanner identity (once per cluster)
kubectl apply -f deploy/rbac.yaml
# Short-lived token for it, instead of a stored long-lived one
kubectl -n shieldops create token shieldops-scanner --duration=1h

make build
./bin/shieldops scan -kubeconfig ~/.kube/config -output report.html
```

`shieldops scan` flags (shared with `shieldops serve`):

| Flag | Default | Meaning |
|---|---|---|
| `-kubeconfig` | `$KUBECONFIG` or `~/.kube/config`; in-cluster if neither exists | kubeconfig path |
| `-context` | current | kubeconfig context |
| `-namespace` | all | namespace to scan |
| `-db` | `$SHIELDOPS_DB` or `shieldops.db` | SQLite database path |
| `-output` | none | HTML report path (`scan` only) |
| `-keep-scans` | `100` | scans kept in the database |
| `-skip-trivy` | `false` | skip CVE scanning |
| `-trivy-cmd` | `trivy` | trivy command; may be wrapped, e.g. `"ssh scan-host trivy"` to pull images on a host with better bandwidth |
| `-trivy-cache` | trivy default | trivy cache directory |
| `-trivy-timeout` | `20m` | time budget for DB update and image scanning |

`shieldops serve` adds `-interval` (default `6h`), `-listen` (default `127.0.0.1:8080`) and `-report` (default: next to the database).

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
cmd/shieldops/      CLI: scan, serve
internal/
  connector/        Kubernetes API client (client-go)
  inventory/        Asset collection (pods, SAs, cluster role bindings, services)
  graph/            SQLite schema, per-scan graph storage, edge builder
  detectors/        Toxic combination detectors, scan comparison
  report/           HTML report (html/template)
pkg/trivy/          CVE scanning via Trivy
deploy/helm/        Helm chart
```

## Development

```bash
make build    # compile
make test     # go test -race -count=1 ./...
make lint     # golangci-lint run ./...
make image    # docker build
```

Local dev environment is in `infra/dev-env/`.

End-to-end check on a test cluster: `test/e2e/fixtures.yaml` creates a deliberately vulnerable namespace that must produce exactly three findings (one per detector). Remove it with `kubectl delete -f test/e2e/fixtures.yaml`.

## Status

MVP — scan pipeline, scan history and in-cluster deployment work. FSTEK control mapping is in progress.

Feedback welcome: open an issue or write to [Habr](https://habr.com/ru/articles/1039100/).
