package detectors_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func om(ns, name string, lbl map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name), Labels: lbl}
}

// replica is a pod of Deployment web.
func replica(name string, spec corev1.PodSpec) corev1.Pod {
	ctrl := true
	meta := om("app", name, map[string]string{"app": "web", "pod-template-hash": "abc"})
	meta.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc", Controller: &ctrl}}
	return corev1.Pod{ObjectMeta: meta, Spec: spec}
}

func scenario() *inventory.Snapshot {
	secretVol := corev1.Volume{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db-creds"}}}
	webSpec := corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}
	return &inventory.Snapshot{
		Pods: []corev1.Pod{
			{ObjectMeta: om("app", "admin-pod", nil), Spec: corev1.PodSpec{ServiceAccountName: "admin-sa"}},
			{ObjectMeta: om("app", "viewer-pod", nil), Spec: corev1.PodSpec{ServiceAccountName: "viewer-sa"}},
			replica("web-abc-1", webSpec),
			replica("web-abc-2", webSpec),
			{ObjectMeta: om("app", "worker", nil), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{ObjectMeta: om("app", "admin-sa", nil)},
			{ObjectMeta: om("app", "viewer-sa", nil)},
			{ObjectMeta: om("app", "default", nil)},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{ObjectMeta: om("", "admin-binding", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "app", Name: "admin-sa"}}},
			{ObjectMeta: om("", "view-binding", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "app", Name: "viewer-sa"}}},
		},
		Services: []corev1.Service{
			{ObjectMeta: om("app", "web-np", nil), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "web"}}},
		},
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := graph.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// loadScan stores snap as a new scan and returns its ID.
func loadScan(t *testing.T, ctx context.Context, db *sql.DB, snap *inventory.Snapshot) int64 {
	t.Helper()
	scanID, err := graph.BeginScan(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := graph.StoreAssets(ctx, db, scanID, snap.Assets()); err != nil {
		t.Fatal(err)
	}
	edges := append(graph.BuildEdges(snap), graph.AttackEdges(snap)...)
	for _, cve := range []map[string]string{
		{"cve_id": "CVE-1", "severity": "CRITICAL", "image": "web:1", "package": "openssl", "installed": "3.0.13", "fixed": "3.0.15"},
		{"cve_id": "CVE-1", "severity": "HIGH", "image": "sidecar:1", "package": "openssl", "installed": "3.0.13", "fixed": "3.0.15"}, // rated differently by another distro
		{"cve_id": "CVE-2", "severity": "HIGH", "image": "web:1", "package": "libx", "installed": "1.2", "fixed": ""},
	} {
		for _, pod := range snap.Pods {
			if pod.Labels["app"] == "web" || pod.Name == "worker" {
				uid := string(pod.UID)
				edges = append(edges, graph.Edge{SourceUID: uid, TargetUID: uid, EdgeType: graph.EdgeHasCVE, Properties: cve})
			}
		}
	}
	if _, err := graph.StoreEdges(ctx, db, scanID, edges); err != nil {
		t.Fatal(err)
	}
	return scanID
}

func TestDetectors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	// Two scans of the same cluster: detectors must only see their own scan.
	loadScan(t, ctx, db, scenario())
	scanID := loadScan(t, ctx, db, scenario())

	tests := []struct {
		detector   string
		wantDescrs []string
	}{
		{"cluster-admin-sa", []string{"Pod/admin-pod in namespace app uses ServiceAccount admin-sa bound to cluster-admin"}},
		// Two replicas of one Deployment give one finding.
		{"exposed-secret", []string{"Secret db-creds mounted in app/Deployment/web exposed via web-np"}},
		{"exposed-cve", []string{"app/Deployment/web has 2 CVEs, top: [CVE-1(CRITICAL) CVE-2(HIGH)]; fixed in openssl 3.0.15"}},
	}
	for _, tt := range tests {
		t.Run(tt.detector, func(t *testing.T) {
			i := slices.IndexFunc(detectors.All, func(d detectors.Detector) bool { return d.ID == tt.detector })
			if i < 0 {
				t.Fatalf("detector %s not registered", tt.detector)
			}
			findings, err := detectors.All[i].Detect(ctx, db, scanID)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.Description)
				if f.Detector != tt.detector || len(f.Fingerprint) != 32 {
					t.Errorf("finding %q: detector %q, fingerprint %q", f.Description, f.Detector, f.Fingerprint)
				}
			}
			if tt.detector == "exposed-cve" {
				want := []detectors.Fix{{Package: "libx", Installed: "1.2"}, {Package: "openssl", Installed: "3.0.13", Fixed: "3.0.15"}}
				if fixes := findings[0].Fixes; !slices.EqualFunc(slices.SortedFunc(slices.Values(fixes), func(a, b detectors.Fix) int { return strings.Compare(a.Package, b.Package) }), want, func(a, b detectors.Fix) bool { return a == b }) {
					t.Errorf("fixes = %+v, want %+v", fixes, want)
				}
			}
			if !slices.Equal(got, tt.wantDescrs) {
				t.Errorf("findings = %q, want %q", got, tt.wantDescrs)
			}
		})
	}
}

func TestRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	all := []string{"cluster-admin-sa", "exposed-secret", "exposed-cve"}
	noCVE := all[:2]

	// run stores a scan, records its findings and finishes it.
	run := func(snap *inventory.Snapshot, ok bool, complete []string) (detectors.Delta, []detectors.Finding) {
		t.Helper()
		scanID := loadScan(t, ctx, db, snap)
		var findings []detectors.Finding
		for _, d := range detectors.All {
			f, err := d.Detect(ctx, db, scanID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(complete, d.ID) {
				f = nil // e.g. trivy skipped: the detector sees no CVEs
			}
			findings = append(findings, f...)
		}
		delta, err := detectors.Record(ctx, db, scanID, findings, complete)
		if err != nil {
			t.Fatal(err)
		}
		if err := graph.FinishScan(ctx, db, scanID, ok); err != nil {
			t.Fatal(err)
		}
		return delta, findings
	}
	countNew := func(ff []detectors.Finding) int {
		n := 0
		for _, f := range ff {
			if f.New {
				n++
			}
		}
		return n
	}

	full := scenario()
	fixed := scenario()
	fixed.Pods = slices.DeleteFunc(fixed.Pods, func(p corev1.Pod) bool { return p.Name == "admin-pod" })
	// Pods restarted under new names: findings are keyed by workload, so nothing changes.
	restarted := scenario()
	restarted.Pods[2].Name, restarted.Pods[2].UID = "web-abc-9", "app/web-abc-9"

	d, ff := run(full, true, all)
	if d.Baseline || countNew(ff) != 0 {
		t.Errorf("first scan: baseline %v, new %d; want no baseline, nothing new", d.Baseline, countNew(ff))
	}

	d, _ = run(restarted, true, all)
	if !d.Baseline || d.New != 0 || len(d.Resolved) != 0 {
		t.Errorf("restarted pods: %+v, want no changes", d)
	}

	d, _ = run(fixed, true, all)
	if d.New != 0 || len(d.Resolved) != 1 || d.Resolved[0].Detector != "cluster-admin-sa" {
		t.Errorf("fixed admin pod: %+v, want one resolved cluster-admin-sa", d)
	}

	// A failed scan is not a baseline: the next scan compares with "fixed".
	run(full, false, all)
	d, ff = run(full, true, all)
	if d.New != 1 || countNew(ff) != 1 || len(d.Resolved) != 0 {
		t.Errorf("admin pod back after failed scan: %+v, want one new", d)
	}

	// Without trivy CVE findings are neither resolved, nor new on the next full scan.
	d, _ = run(full, true, noCVE)
	if d.New != 0 || len(d.Resolved) != 0 {
		t.Errorf("scan without trivy: %+v, want no changes", d)
	}
	d, _ = run(full, true, all)
	if d.New != 0 || len(d.Resolved) != 0 {
		t.Errorf("full scan after scan without trivy: %+v, want no changes", d)
	}
}
