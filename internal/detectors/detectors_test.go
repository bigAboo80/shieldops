package detectors_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// These tests need a real PostgreSQL: SHIELDOPS_TEST_DB=postgres://... go test ./...
// They share one database, so they do not run in parallel.

func om(ns, name string, lbl map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name), Labels: lbl}
}

func scenario() *inventory.Snapshot {
	web := map[string]string{"app": "web"}
	secretVol := corev1.Volume{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db-creds"}}}
	return &inventory.Snapshot{
		Pods: []corev1.Pod{
			{ObjectMeta: om("app", "admin-pod", nil), Spec: corev1.PodSpec{ServiceAccountName: "admin-sa"}},
			{ObjectMeta: om("app", "viewer-pod", nil), Spec: corev1.PodSpec{ServiceAccountName: "viewer-sa"}},
			{ObjectMeta: om("app", "web", web), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}},
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
			{ObjectMeta: om("app", "web-np", nil), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: web}},
		},
		Secrets: []metav1.PartialObjectMetadata{{ObjectMeta: om("app", "db-creds", nil)}},
	}
}

func loadGraph(t *testing.T, ctx context.Context, db *sql.DB, snap *inventory.Snapshot) {
	t.Helper()
	if err := graph.ReplaceAssets(ctx, db, snap.Assets()); err != nil {
		t.Fatal(err)
	}
	edges := graph.BuildEdges(snap)
	for _, cve := range []map[string]string{
		{"cve_id": "CVE-1", "severity": "CRITICAL", "image": "web:1"},
		{"cve_id": "CVE-1", "severity": "CRITICAL", "image": "sidecar:1"},
		{"cve_id": "CVE-2", "severity": "HIGH", "image": "web:1"},
	} {
		edges = append(edges, graph.Edge{SourceUID: "app/web", TargetUID: "app/web", EdgeType: graph.EdgeHasCVE, Properties: cve})
		edges = append(edges, graph.Edge{SourceUID: "app/worker", TargetUID: "app/worker", EdgeType: graph.EdgeHasCVE, Properties: cve})
	}
	if _, err := graph.StoreEdges(ctx, db, edges); err != nil {
		t.Fatal(err)
	}
}

func TestDetectors(t *testing.T) {
	dsn := os.Getenv("SHIELDOPS_TEST_DB")
	if dsn == "" {
		t.Skip("SHIELDOPS_TEST_DB not set")
	}
	ctx := context.Background()
	db, err := graph.InitDB(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Load twice: a repeated scan must not duplicate edges or findings.
	loadGraph(t, ctx, db, scenario())
	loadGraph(t, ctx, db, scenario())

	tests := []struct {
		name       string
		detect     func(context.Context, *sql.DB) ([]detectors.Finding, error)
		wantDescrs []string
	}{
		{"cluster-admin service account", detectors.DetectClusterAdminSA,
			[]string{"Pod admin-pod in namespace app uses ServiceAccount admin-sa bound to cluster-admin"}},
		{"secret in exposed pod", detectors.DetectExposedSecrets,
			[]string{"Secret db-creds mounted in pod app/web exposed via web-np"}},
		{"exposed pod with CVE", detectors.DetectExposedPodWithCVE,
			[]string{"Pod app/web has 2 unique CVEs, top: [CVE-1(CRITICAL) CVE-2(HIGH)]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := tt.detect(ctx, db)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.Description)
			}
			if len(got) != len(tt.wantDescrs) {
				t.Fatalf("findings = %q, want %q", got, tt.wantDescrs)
			}
			for i := range got {
				if got[i] != tt.wantDescrs[i] {
					t.Errorf("finding[%d] = %q, want %q", i, got[i], tt.wantDescrs[i])
				}
			}
		})
	}
}
