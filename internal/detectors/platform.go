package detectors

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

// DefaultPlatformNamespaces hold components of Kubernetes and of the
// cluster's infrastructure: the provider of the cluster sets them up, or
// they need their privileges by design, so an application team rarely
// fixes their findings.
var DefaultPlatformNamespaces = []string{
	"kube-system", "kube-public", "kube-node-lease",
	"kube-flannel", "calico-system", "tigera-operator", "cilium",
	"local-path-storage", "ingress-nginx", "cert-manager", "metallb-system",
	"monitoring", "yandex-system",
}

// PlatformNamespaces builds the list of platform namespaces from the
// -platform-namespaces flag: its comma-separated namespaces are added to the
// defaults, and "-" among them drops the defaults. own is the namespace
// ShieldOps runs in, empty when unknown.
func PlatformNamespaces(flag, own string) []string {
	var out []string
	extra := splitComma(flag)
	if !slices.Contains(extra, "-") {
		out = slices.Clone(DefaultPlatformNamespaces)
	}
	for _, ns := range append(extra, own) {
		if ns != "" && ns != "-" && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// MarkPlatform sets Finding.Platform: the finding's workload is in a
// platform namespace, or is a static pod of the control plane. Platform
// findings are scanned and take part in the graph as before; only how
// they are shown changes. A finding without a namespace (cluster-wide) is
// never platform.
func MarkPlatform(ctx context.Context, db *sql.DB, scanID int64, findings []Finding, namespaces []string) error {
	static, err := staticPods(ctx, db, scanID)
	if err != nil {
		return err
	}
	for i := range findings {
		f := &findings[i]
		f.Platform = isPlatform(*f, namespaces, static)
	}
	return nil
}

func isPlatform(f Finding, namespaces []string, static map[string]bool) bool {
	if f.Namespace == "" {
		return false
	}
	if slices.Contains(namespaces, f.Namespace) {
		return true
	}
	if len(f.Targets) > 0 {
		t := f.Targets[0]
		return t.Kind == "Pod" && static[t.Namespace+"/Pod/"+t.Name]
	}
	return false
}

// staticPods returns the workloads ("namespace/Pod/name") of static pods.
func staticPods(ctx context.Context, db *sql.DB, scanID int64) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT a.namespace, a.workload
		FROM assets a JOIN asset_facts f ON f.scan_id = a.scan_id AND f.uid = a.uid
		WHERE a.scan_id = ? AND a.kind = 'Pod' AND f.kind = ?
	`, scanID, inventory.FactStaticPod)
	if err != nil {
		return nil, fmt.Errorf("query static pods: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ns, workload string
		if err := rows.Scan(&ns, &workload); err != nil {
			return nil, fmt.Errorf("scan static pod: %w", err)
		}
		out[ns+"/"+workload] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate static pods: %w", err)
	}
	return out, nil
}
