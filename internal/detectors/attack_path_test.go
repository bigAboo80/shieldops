package detectors_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func attackPaths(t *testing.T, snap *inventory.Snapshot) []detectors.Finding {
	t.Helper()
	ctx := context.Background()
	db := openDB(t)
	fs, err := detectors.DetectAttackPaths(ctx, db, loadScan(t, ctx, db, snap))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// TestAttackPathFingerprints pins the fingerprints of attack paths and
// checks they survive recreated objects and changes inside the path.
func TestAttackPathFingerprints(t *testing.T) {
	t.Parallel()
	fingerprints := func(fs []detectors.Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Fingerprint)
		}
		slices.Sort(out)
		return out
	}
	want := fingerprints(attackPaths(t, scenario()))
	if len(want) == 0 {
		t.Fatal("no attack paths in the scenario")
	}
	if pinned := []string{"4014d894011defdd7c1ce0edc833c924"}; !slices.Equal(want, pinned) {
		t.Errorf("fingerprints changed: %q, want %q", want, pinned)
	}

	recreated := scenario()
	for i := range recreated.Pods {
		recreated.Pods[i].UID = types.UID("new-" + recreated.Pods[i].Name)
	}
	for i := range recreated.Services {
		recreated.Services[i].UID = types.UID("new-svc-" + recreated.Services[i].Name)
		recreated.Services[i].Name = "renamed" // a step in the middle of the path
	}
	if got := fingerprints(attackPaths(t, recreated)); !slices.Equal(got, want) {
		t.Errorf("fingerprints after recreating objects = %q, want %q", got, want)
	}
}

// TestOwnNamespace runs every detector on ShieldOps as the Helm chart
// installs it: the product must not be a finding of its own (STRATEGY 2.4).
func TestOwnNamespace(t *testing.T) {
	t.Parallel()
	no, yes := false, true
	uid := int64(65532)
	ns := "shieldops"
	pod := deployment(ns, "shieldops", 1, corev1.PodSpec{
		ServiceAccountName: "shieldops",
		NodeName:           "n1",
		SecurityContext:    &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid},
		Containers: []corev1.Container{container("shieldops", "shieldops:0.2@sha256:0123456789abcdef", &corev1.SecurityContext{
			AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}})},
		Volumes: []corev1.Volume{{Name: "admin", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "shieldops-admin"}}}},
	})
	readOnly := rbacv1.ClusterRole{ObjectMeta: om("", "shieldops-scanner", nil), Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "serviceaccounts", "services", "nodes"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies", "ingresses"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterrolebindings", "clusterroles", "rolebindings", "roles"}, Verbs: []string{"get", "list"}},
	}}
	snap := func(expose bool) *inventory.Snapshot {
		s := &inventory.Snapshot{
			Pods:                pod,
			Nodes:               []corev1.Node{{ObjectMeta: om("", "n1", nil)}},
			ServiceAccounts:     []corev1.ServiceAccount{{ObjectMeta: om(ns, "shieldops", nil)}},
			ClusterRoles:        []rbacv1.ClusterRole{readOnly},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{ObjectMeta: om("", "shieldops-scanner", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "shieldops-scanner"}, Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: "shieldops"}}}},
			NetworkPolicies: []networkingv1.NetworkPolicy{{ObjectMeta: om(ns, "np-shieldops", nil), Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "shieldops"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}},
		}
		if expose { // web.expose: a ClusterIP Service for the ingress controller
			s.Services = []corev1.Service{{ObjectMeta: om(ns, "svc-shieldops", nil), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "shieldops"}}}}
		}
		return s
	}
	for _, expose := range []bool{false, true} {
		ctx := context.Background()
		db := openDB(t)
		id := loadScan(t, ctx, db, snap(expose))
		for _, d := range detectors.All {
			fs, err := d.Detect(ctx, db, id)
			if err != nil {
				t.Fatalf("%s: %v", d.ID, err)
			}
			for _, f := range fs {
				t.Errorf("expose=%v: %s: %s", expose, d.ID, f.Description)
			}
		}
	}
}

// TestSecretsThroughRights: an Internet-facing controller that may read
// every Secret of the cluster is one finding, not one per Secret.
func TestSecretsThroughRights(t *testing.T) {
	t.Parallel()
	secretPod := func(ns, name, secret string) []corev1.Pod {
		return deployment(ns, name, 1, corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}}}}})
	}
	snap := func(secrets int) *inventory.Snapshot {
		s := &inventory.Snapshot{
			Pods:            deployment("kube-system", "traefik", 1, corev1.PodSpec{ServiceAccountName: "traefik"}),
			ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: om("kube-system", "traefik", nil)}},
			ClusterRoles: []rbacv1.ClusterRole{{ObjectMeta: om("", "traefik", nil), Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}}}}},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{ObjectMeta: om("", "traefik", nil), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "traefik"},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "kube-system", Name: "traefik"}}}},
			Services: []corev1.Service{{ObjectMeta: om("kube-system", "traefik-lb", nil),
				Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "traefik"}}}},
		}
		for i := range secrets {
			s.Pods = append(s.Pods, secretPod("shop", fmt.Sprintf("app%d", i), fmt.Sprintf("secret%d", i))...)
		}
		return s
	}
	cases := []struct {
		name    string
		secrets int
		desc    string
	}{
		{"one Secret", 1, "kube-system/Deployment/traefik leads to Secret: shop/secret0 in 4 steps"},
		{"many Secrets", 3, "kube-system/Deployment/traefik can read 3 Secrets through the rights of SA: kube-system/traefik"},
	}
	var fps []string
	for _, c := range cases {
		fs := attackPaths(t, snap(c.secrets))
		if len(fs) != 1 {
			t.Fatalf("%s: %d findings, want 1: %v", c.name, len(fs), fs)
		}
		f := fs[0]
		if !strings.HasPrefix(f.Description, c.desc) {
			t.Errorf("%s: description %q, want prefix %q", c.name, f.Description, c.desc)
		}
		if ru := f.In("ru").Description; ru == f.Description {
			t.Errorf("%s: description not translated: %q", c.name, ru)
		}
		fps = append(fps, f.Fingerprint)
	}
	if fps[0] != fps[1] {
		t.Errorf("fingerprint changes with the number of Secrets: %q", fps)
	}
}
