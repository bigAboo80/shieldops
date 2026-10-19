# ShieldOps

Agentless Kubernetes security scanner. Detects toxic privilege combinations, exposed secrets, and CVEs. Generates an HTML report with findings mapped to FSTEK controls, and tells you what changed since the previous scan.

This repository is the open part: the `scan` CLI, the graph, the detectors and the HTML report. The image and the Helm chart run ShieldOps inside your cluster, with a web interface, for free on one cluster.

No agents. No SaaS. No data leaves your cluster.

## Install in your cluster (10 minutes)

```bash
helm install shieldops oci://ghcr.io/bigaboo80/charts/shieldops -n shieldops --create-namespace
```

The first results show up in seconds, image vulnerabilities in 1–3 minutes. The install prints how to get the admin password and open the web interface (`kubectl port-forward`, nothing is exposed by default). The home page is **Fix this week**: up to five actions for your applications, with a ready patch or fix script; Kubernetes components are on a tab of their own.

**Free plan**, no license: one cluster, every check and attack path, the home page, decisions on findings (accepted risk, false positive), fix patches and scripts.
**Pro**, with a license: notifications and digests (Telegram, Mattermost), due dates (SLA), Merge Requests with fixes to your GitOps repository, more users and roles, SSO, signed and PDF reports, FSTEK measures and the period report. An expired license never stops scanning and never deletes data.

## What it detects

- **Cluster-admin ServiceAccounts in running workloads** — workloads whose ServiceAccount is bound to `cluster-admin`
- **Secrets in exposed workloads** — workloads mounting secrets (volumes, projected volumes, `envFrom`, `env`) while exposed via LoadBalancer/NodePort
- **Exposed workloads with known CVEs** — LoadBalancer/NodePort workloads running images with CRITICAL/HIGH CVEs

Each finding includes a full attack path: how an attacker could chain the issue into cluster compromise.

- **Attack paths** — the shortest ways from the Internet (LoadBalancer/NodePort Services, Ingresses) through workloads, their ServiceAccount tokens and effective RBAC rights to Secrets, nodes and RBAC escalation, ranked by an explainable risk score of 0–100 and drawn as a diagram at the top of the report

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
| `-exclude-namespaces` | none | comma-separated namespaces to skip |
| `-platform-namespaces` | none | comma-separated namespaces of cluster components, added to the built-in list (`kube-system`, `ingress-nginx`, `monitoring`, ...); `-` drops the built-in list. Their findings are marked as platform findings |
| `-db` | `$SHIELDOPS_DB` or `shieldops.db` | SQLite database path |
| `-output` | none | HTML report path |
| `-lang` | `ru` | report language, `ru` or `en` |
| `-timezone` | `Europe/Moscow` | time zone of the report |
| `-fstek` | none | FSTEK order of the measures table: `117` or `17`; without it the report has no measures table |
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
- FSTEK measures table with `-fstek`: Order No. 117 or No. 17


### Signed reports and `shieldops verify`

A report can be signed with Ed25519 so an auditor can check it was not changed. The signature is detached: `report.html.sig` next to `report.html`, a JSON file with the algorithm, the SHA-256 of the report, the time, the fingerprint of the public key and the signature over them. The report itself shows the fingerprint and the SHA-256 of the scan data in its footer (the hash of the file cannot be inside the file).

```bash
shieldops keygen -out keys                       # keys/shieldops-signing.key (0600) and .pub
shieldops scan -sign-key-file keys/shieldops-signing.key -output report.html
shieldops verify -pub keys/shieldops-signing.pub report.html   # report.html.sig is found next to it
shieldops keygen -show-pub -key keys/shieldops-signing.key     # print the public key again
```

`verify` exits with 0 when the signature is valid, otherwise it says why (the report was changed, the signature file was changed, another key) and exits with 1. Give auditors the `.pub` file only. This is not a qualified electronic signature: a legally binding one needs GOST cryptography.

Until a FSTEK expert confirms the mapping of findings to measures, the measures table is marked as a draft (`detectors.MappingReviewed`).

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

End-to-end check on a test cluster: `test/e2e/fixtures.yaml` creates a deliberately vulnerable namespace that must produce exactly nine findings (one per detector). Remove it with `kubectl delete -f test/e2e/fixtures.yaml`.

## Full product

The image runs the full product: scheduled scans, the web interface, finding triage that survives rescans, an audit log and the Helm chart; a license turns on the Pro functions. It is self-hosted and works in closed networks: copy the image to your registry and set `image.repository`.

Feedback and pilots: open an issue or write to [Habr](https://habr.com/ru/articles/1039100/).
