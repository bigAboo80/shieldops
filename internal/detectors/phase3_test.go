package detectors_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// deployment returns the replicas of Deployment name in namespace ns.
func deployment(ns, name string, replicas int, spec corev1.PodSpec) []corev1.Pod {
	ctrl := true
	var pods []corev1.Pod
	for i := range replicas {
		meta := om(ns, fmt.Sprintf("%s-abc-%d", name, i), map[string]string{"app": name, "pod-template-hash": "abc"})
		meta.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: name + "-abc", Controller: &ctrl}}
		pods = append(pods, corev1.Pod{ObjectMeta: meta, Spec: spec})
	}
	return pods
}

func container(name, image string, sc *corev1.SecurityContext) corev1.Container {
	return corev1.Container{Name: name, Image: image, SecurityContext: sc}
}

func hostPathVolume(p string) corev1.Volume {
	return corev1.Volume{Name: "v" + p, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: p}}}
}

func lbService(ns, app string) corev1.Service {
	return corev1.Service{ObjectMeta: om(ns, "svc-"+app, nil),
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": app}}}
}

func wildcardSnapshot() *inventory.Snapshot {
	yes, no := true, false
	pinned := "app:1.0@sha256:0123456789abcdef"
	var pods []corev1.Pod
	for _, p := range [][]corev1.Pod{
		// exposed + privileged: Critical; the init container is checked too
		deployment("p3", "priv-exposed", 2, corev1.PodSpec{Containers: []corev1.Container{container("c", pinned, &corev1.SecurityContext{Privileged: &yes})}}),
		// SYS_ADMIN with privilege escalation, not exposed: High
		deployment("p3", "sysadmin", 1, corev1.PodSpec{
			InitContainers: []corev1.Container{container("init", pinned, &corev1.SecurityContext{
				AllowPrivilegeEscalation: &yes, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}})},
			Containers: []corev1.Container{container("c", pinned, nil)},
		}),
		// privilege escalation alone, SYS_ADMIN alone and explicit false: all safe
		deployment("p3", "safe-escalation", 1, corev1.PodSpec{Containers: []corev1.Container{
			container("a", pinned, &corev1.SecurityContext{AllowPrivilegeEscalation: &yes}),
			container("b", pinned, &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}}),
			container("c", pinned, &corev1.SecurityContext{Privileged: &no}),
		}}),
		deployment("p3", "host", 2, corev1.PodSpec{HostNetwork: true, HostPID: true, Containers: []corev1.Container{container("c", pinned, nil)}}),
		deployment("p3", "paths", 2, corev1.PodSpec{
			Volumes:    []corev1.Volume{hostPathVolume("/var/run/docker.sock"), hostPathVolume("/data/logs"), hostPathVolume("/etc/kubernetes/pki")},
			Containers: []corev1.Container{container("c", pinned, nil)},
		}),
		deployment("p3", "floating", 2, corev1.PodSpec{Containers: []corev1.Container{
			container("a", "nginx", nil), container("b", "reg.local:5000/app:latest", nil),
			container("c", "nginx:1.27", nil), container("d", "nginx:latest@sha256:abc", nil),
		}}),
		// ServiceAccount wild (wildcard role via ClusterRoleBinding), exposed
		deployment("p3", "rbac-exposed", 2, corev1.PodSpec{ServiceAccountName: "wild", Containers: []corev1.Container{container("c", pinned, nil)}}),
		deployment("p3", "rbac-internal", 1, corev1.PodSpec{ServiceAccountName: "ns-wild", Containers: []corev1.Container{container("c", pinned, nil)}}),
		deployment("p3", "rbac-safe", 1, corev1.PodSpec{ServiceAccountName: "narrow", Containers: []corev1.Container{container("c", pinned, nil)}}),
		// another namespace, fully covered by a default-deny policy
		deployment("covered", "web", 1, corev1.PodSpec{Containers: []corev1.Container{container("c", pinned, nil)}}),
	} {
		pods = append(pods, p...)
	}
	sas := func(ns string, names ...string) (res []corev1.ServiceAccount) {
		for _, n := range names {
			res = append(res, corev1.ServiceAccount{ObjectMeta: om(ns, n, nil)})
		}
		return
	}
	subject := func(name string) []rbacv1.Subject {
		return []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "p3", Name: name}}
	}
	return &inventory.Snapshot{
		Pods:            pods,
		ServiceAccounts: slices.Concat(sas("p3", "default", "wild", "ns-wild", "narrow"), sas("covered", "default")),
		Services: []corev1.Service{
			lbService("p3", "priv-exposed"), lbService("p3", "rbac-exposed"),
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{
			{ObjectMeta: om("covered", "deny-all", nil)}, // empty selector selects every pod
			{ObjectMeta: om("p3", "only-host", nil), Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "host"}}}},
		},
		ClusterRoles: []rbacv1.ClusterRole{
			{ObjectMeta: om("", "wild-cr", nil), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}}},
			{ObjectMeta: om("", "narrow-cr", nil), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}},
			{ObjectMeta: om("", "cluster-admin", nil), Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
		},
		Roles: []rbacv1.Role{
			{ObjectMeta: om("p3", "wild-role", nil), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"*"}}}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{ObjectMeta: om("", "wild-crb", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "wild-cr"}, Subjects: subject("wild")},
			{ObjectMeta: om("", "narrow-crb", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "narrow-cr"}, Subjects: subject("narrow")},
			// reported by cluster-admin-sa, not again as wildcard
			{ObjectMeta: om("", "admin-crb", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, Subjects: subject("narrow")},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{ObjectMeta: om("p3", "wild-rb", nil), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "wild-role"}, Subjects: subject("ns-wild")},
		},
	}
}

func TestPhase3Detectors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	// Two scans of the same cluster: detectors must only see their own scan,
	// and fingerprints must not change between them.
	first := loadScan(t, ctx, db, wildcardSnapshot())
	second := loadScan(t, ctx, db, wildcardSnapshot())

	tests := []struct {
		detector string
		want     []string // "Severity: description"
	}{
		{"privileged-container", []string{
			"Critical: p3/Deployment/priv-exposed runs privileged containers: c",
			"High: p3/Deployment/sysadmin runs privileged containers: init",
		}},
		{"host-namespaces", []string{"High: p3/Deployment/host uses hostNetwork, hostPID"}},
		{"host-path", []string{
			"High: p3/Deployment/paths mounts node path /data/logs",
			"Critical: p3/Deployment/paths mounts node path /etc/kubernetes/pki",
			"Critical: p3/Deployment/paths mounts node path /var/run/docker.sock",
		}},
		{"latest-tag", []string{"Low: p3/Deployment/floating uses unpinned images: nginx, reg.local:5000/app:latest"}},
		{"no-network-policy", []string{"Medium: Namespace p3: 8 workloads (12 pods) are not selected by any NetworkPolicy"}},
		{"wildcard-rbac", []string{
			"High: p3/Deployment/rbac-internal uses ServiceAccount p3/ns-wild bound to Role wild-role with \"*\" in verbs (namespace scope)",
			"Critical: p3/Deployment/rbac-exposed uses ServiceAccount p3/wild bound to ClusterRole wild-cr with \"*\" in resources (cluster scope)",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.detector, func(t *testing.T) {
			t.Parallel()
			i := slices.IndexFunc(detectors.All, func(d detectors.Detector) bool { return d.ID == tt.detector })
			if i < 0 {
				t.Fatalf("detector %s not registered", tt.detector)
			}
			d := detectors.All[i]
			if d.NeedsCVE {
				t.Errorf("%s must not need trivy", d.ID)
			}
			run := func(scanID int64) (got, prints []string) {
				findings, err := d.Detect(ctx, db, scanID)
				if err != nil {
					t.Fatalf("detect: %v", err)
				}
				for _, f := range findings {
					got = append(got, f.Severity+": "+f.Description)
					prints = append(prints, f.Fingerprint)
					if f.Detector != tt.detector || len(f.Fingerprint) != 32 || len(f.FSTEKControls) == 0 ||
						f.Recommendation == "" || f.Remediation == "" || len(f.AttackPath) == 0 {
						t.Errorf("incomplete finding %+v", f)
					}
				}
				return
			}
			got, prints := run(first)
			slices.Sort(got)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("findings = %q, want %q", got, want)
			}
			if _, prints2 := run(second); !slices.Equal(prints, prints2) {
				t.Errorf("fingerprints differ between scans: %v vs %v", prints, prints2)
			}
			if len(slices.Compact(slices.Sorted(slices.Values(prints)))) != len(prints) {
				t.Errorf("duplicate fingerprints: %v", prints)
			}
		})
	}
}

func TestNoNetworkPolicyCovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	snap := wildcardSnapshot()
	// Only the covered namespace remains: a default-deny policy selects its pods.
	snap.Pods = slices.DeleteFunc(snap.Pods, func(p corev1.Pod) bool { return p.Namespace != "covered" })
	findings, err := detectors.DetectNoNetworkPolicy(ctx, db, loadScan(t, ctx, db, snap))
	if err != nil || len(findings) != 0 {
		t.Errorf("findings = %v, err = %v; want none", findings, err)
	}
}
