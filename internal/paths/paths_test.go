package paths_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	"github.com/bigAboo80/shieldops/internal/paths"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func om(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name)}
}

func secretVol(name string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: name}}}
}

func pod(ns, name, sa, node string, labels map[string]string, spec corev1.PodSpec) corev1.Pod {
	spec.ServiceAccountName, spec.NodeName = sa, node
	meta := om(ns, name)
	meta.Labels = labels
	return corev1.Pod{ObjectMeta: meta, Spec: spec}
}

// reference is a shop: an Ingress in front of web, whose token reads the
// Secrets of the namespace, and a privileged api behind a LoadBalancer
// without a token. db is internal.
func reference() *inventory.Snapshot {
	yes, no := true, false
	return &inventory.Snapshot{
		Nodes: []corev1.Node{{ObjectMeta: om("", "n1")}},
		Pods: []corev1.Pod{
			pod("shop", "web", "web-sa", "n1", map[string]string{"app": "web"}, corev1.PodSpec{Volumes: []corev1.Volume{secretVol("tls")}}),
			pod("shop", "api", "default", "n1", map[string]string{"app": "api"}, corev1.PodSpec{AutomountServiceAccountToken: &no,
				Containers: []corev1.Container{{Name: "c", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}),
			pod("shop", "db", "default", "n2", map[string]string{"app": "db"}, corev1.PodSpec{Volumes: []corev1.Volume{secretVol("db-pass")}}),
		},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: om("shop", "web-sa")}, {ObjectMeta: om("shop", "default")}},
		Services: []corev1.Service{
			{ObjectMeta: om("shop", "svc-front"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}},
			{ObjectMeta: om("shop", "svc-api"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "api"}}},
			{ObjectMeta: om("shop", "svc-db"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "db"}}},
		},
		Ingresses: []networkingv1.Ingress{{ObjectMeta: om("shop", "ing"), Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "svc-front"}}}}},
		Roles: []rbacv1.Role{{ObjectMeta: om("shop", "reader"), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}}},
		RoleBindings: []rbacv1.RoleBinding{{ObjectMeta: om("shop", "web-reads"), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "web-sa"}}}},
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

// load stores snap with extra edges, e.g. CVEs, and returns its graph.
func load(t *testing.T, snap *inventory.Snapshot, extra ...graph.Edge) *paths.Graph {
	t.Helper()
	ctx := context.Background()
	db := openDB(t)
	id, err := graph.BeginScan(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := graph.StoreAssets(ctx, db, id, snap.Assets()); err != nil {
		t.Fatal(err)
	}
	edges := slices.Concat(graph.BuildEdges(snap), graph.AttackEdges(snap), extra, graph.LateralEdges(snap, extra))
	if _, err := graph.StoreEdges(ctx, db, id, edges); err != nil {
		t.Fatal(err)
	}
	g, err := paths.Load(ctx, db, id)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func cve(uid, severity, fixed string) graph.Edge {
	return graph.Edge{SourceUID: uid, TargetUID: uid, EdgeType: graph.EdgeHasCVE,
		Properties: map[string]string{"cve_id": "CVE-" + severity, "severity": severity, "fixed": fixed}}
}

// show renders paths as "score: step -EDGE-> step ...".
func show(ps []paths.Path) []string {
	var out []string
	for _, p := range ps {
		var b strings.Builder
		fmt.Fprintf(&b, "%d:", p.Score.Total)
		for _, s := range p.Steps {
			if s.Edge != "" {
				fmt.Fprintf(&b, " -%s->", s.Edge)
			}
			b.WriteString(" " + s.Label())
		}
		out = append(out, b.String())
	}
	return out
}

func TestPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		snap *inventory.Snapshot
		cves []graph.Edge
		want []string
	}{
		{"reference graph", reference(), []graph.Edge{cve("shop/web", "CRITICAL", "1.2")}, []string{
			// api can exploit web next to it: its CVE counts on this path too.
			"82: Internet -EXPOSES-> Service: shop/svc-api -ROUTES_TO-> shop/Pod/api -CAN_REACH-> shop/Pod/web -HAS_TOKEN-> SA: shop/web-sa -CAN_READ_SECRETS-> Secret: shop/db-pass",
			"79: Internet -EXPOSES-> Ingress: shop/ing -ROUTES_TO-> Service: shop/svc-front -ROUTES_TO-> shop/Pod/web -HAS_TOKEN-> SA: shop/web-sa -CAN_READ_SECRETS-> Secret: shop/db-pass",
			"77: Internet -EXPOSES-> Service: shop/svc-api -ROUTES_TO-> shop/Pod/api -CAN_REACH-> shop/Pod/web -MOUNTS_SECRET-> Secret: shop/tls",
			"74: Internet -EXPOSES-> Ingress: shop/ing -ROUTES_TO-> Service: shop/svc-front -ROUTES_TO-> shop/Pod/web -MOUNTS_SECRET-> Secret: shop/tls",
			// api has no token: automountServiceAccountToken: false ends its path at the node.
			"62: Internet -EXPOSES-> Service: shop/svc-api -ROUTES_TO-> shop/Pod/api -ESCAPES_TO_NODE-> Node: n1",
		}},
		{"lateral movement to a vulnerable internal workload", func() *inventory.Snapshot {
			s := reference()
			s.Ingresses, s.RoleBindings = nil, nil
			return s
		}(), []graph.Edge{cve("shop/db", "HIGH", "")}, []string{
			"62: Internet -EXPOSES-> Service: shop/svc-api -ROUTES_TO-> shop/Pod/api -ESCAPES_TO_NODE-> Node: n1",
			"62: Internet -EXPOSES-> Service: shop/svc-api -ROUTES_TO-> shop/Pod/api -CAN_REACH-> shop/Pod/db -MOUNTS_SECRET-> Secret: shop/db-pass",
		}},
		{"nothing exposed: no paths", func() *inventory.Snapshot {
			s := reference()
			s.Ingresses, s.Services = nil, nil
			return s
		}(), nil, nil},
		{"empty graph", &inventory.Snapshot{}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := load(t, tt.snap, tt.cves...).Paths()
			if got := show(ps); !slices.Equal(got, tt.want) {
				t.Errorf("paths =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
			for _, p := range ps {
				seen := map[string]bool{}
				for _, s := range p.Steps {
					if seen[s.Label()] {
						t.Errorf("cycle at %s in %v", s.Label(), show([]paths.Path{p}))
					}
					seen[s.Label()] = true
				}
				if len(p.Steps)-1 > paths.MaxDepth {
					t.Errorf("path of %d edges, max %d", len(p.Steps)-1, paths.MaxDepth)
				}
			}
		})
	}
}

// chain makes web reach a Secret through hops ServiceAccounts, each allowed
// to create pods in the namespace of the next.
func chain(hops int) *inventory.Snapshot {
	s := &inventory.Snapshot{
		Pods:            []corev1.Pod{pod("ns0", "web", "sa", "", map[string]string{"app": "web"}, corev1.PodSpec{})},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: om("ns0", "sa")}},
		Services:        []corev1.Service{{ObjectMeta: om("ns0", "svc-web"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "web"}}}},
	}
	rule := func(res, verb string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{res}, Verbs: []string{verb}}
	}
	for i := 1; i <= hops+1; i++ {
		ns, prev := fmt.Sprintf("ns%d", i), fmt.Sprintf("ns%d", i-1)
		r := rule("pods", "create")
		if i == hops+1 { // the last one reads Secrets of its own namespace
			ns, r = prev, rule("secrets", "get")
			s.Pods = append(s.Pods, pod(ns, "holder", "", "", nil, corev1.PodSpec{Volumes: []corev1.Volume{secretVol("key")}}))
		} else {
			s.ServiceAccounts = append(s.ServiceAccounts, corev1.ServiceAccount{ObjectMeta: om(ns, "sa")})
		}
		s.Roles = append(s.Roles, rbacv1.Role{ObjectMeta: om(ns, "r"+prev), Rules: []rbacv1.PolicyRule{r}})
		s.RoleBindings = append(s.RoleBindings, rbacv1.RoleBinding{ObjectMeta: om(ns, "rb"+prev),
			RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "r" + prev}, Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: prev, Name: "sa"}}})
	}
	return s
}

func TestMaxDepth(t *testing.T) {
	t.Parallel()
	// Internet, Service, web, its SA: 3 edges; each hop 1, the read 1.
	for _, tt := range []struct {
		hops  int
		found bool
	}{{0, true}, {2, true}, {3, false}} {
		t.Run(fmt.Sprint(tt.hops), func(t *testing.T) {
			t.Parallel()
			found := slices.ContainsFunc(load(t, chain(tt.hops)).Paths(), func(p paths.Path) bool { return p.Target.Kind == "Secret" })
			if found != tt.found {
				t.Errorf("%d hops: path to the Secret found = %v, want %v", tt.hops, found, tt.found)
			}
		})
	}
}

func TestBlastRadius(t *testing.T) {
	t.Parallel()
	got := load(t, reference()).BlastRadius()
	want := []paths.Blast{
		// api reaches node n1, which hosts web: its Secrets too.
		{Namespace: "shop", Workload: "Pod/api", Secrets: 2, Namespaces: 1, Nodes: 1},
		{Namespace: "shop", Workload: "Pod/db", Secrets: 1, Namespaces: 1},
		{Namespace: "shop", Workload: "Pod/web", Secrets: 2, Namespaces: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("blast radius = %+v, want %+v", got, want)
	}
}

func TestScore(t *testing.T) {
	t.Parallel()
	// The path through the Ingress to the Secret mounted in web: exposure 30,
	// mount 10, blast radius 2 Secrets + 1 namespace = 4, and the CVE of web.
	tests := []struct {
		name     string
		cves     []graph.Edge
		want     int
		severity string
	}{
		{"no CVE", nil, 44, "Medium"},
		{"LOW does not count", []graph.Edge{cve("shop/web", "LOW", "1.0")}, 44, "Medium"},
		{"HIGH", []graph.Edge{cve("shop/web", "HIGH", "")}, 59, "Medium"},
		{"HIGH with a fix", []graph.Edge{cve("shop/web", "HIGH", "1.1")}, 64, "High"},
		{"CRITICAL", []graph.Edge{cve("shop/web", "CRITICAL", "")}, 69, "High"},
		{"CRITICAL and a fixed HIGH: the fix of the worst counts", []graph.Edge{cve("shop/web", "CRITICAL", ""), cve("shop/web", "HIGH", "1.1")}, 69, "High"},
		{"CRITICAL with a fix", []graph.Edge{cve("shop/web", "CRITICAL", "1.2")}, 74, "High"},
	}
	prev := 0
	for _, tt := range tests {
		// Not parallel: each case must score at least as high as the one before.
		snap := reference()
		snap.Services = snap.Services[:1] // only the Ingress: no lateral path from api
		var got paths.Path
		for _, p := range load(t, snap, tt.cves...).Paths() {
			if p.Target.Name == "tls" && p.Workload.Name == "Pod/web" {
				got = p
			}
		}
		if got.Score.Total != tt.want || got.Score.Severity() != tt.severity {
			t.Errorf("%s: score %d (%s), want %d (%s); %+v", tt.name, got.Score.Total, got.Score.Severity(), tt.want, tt.severity, got.Score)
		}
		if got.Score.Total < prev {
			t.Errorf("%s: score fell from %d to %d with a worse CVE", tt.name, prev, got.Score.Total)
		}
		prev = got.Score.Total
	}
}

func TestSeverity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		total int
		want  string
	}{{100, "Critical"}, {80, "Critical"}, {79, "High"}, {60, "High"}, {59, "Medium"}, {40, "Medium"}, {39, "Low"}, {0, "Low"}} {
		if got := (paths.Score{Total: tt.total}).Severity(); got != tt.want {
			t.Errorf("Severity(%d) = %s, want %s", tt.total, got, tt.want)
		}
	}
}
