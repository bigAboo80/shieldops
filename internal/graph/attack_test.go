package graph

import (
	"slices"
	"testing"

	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func onNode(ns, name, node string, spec corev1.PodSpec) corev1.Pod {
	spec.NodeName = node
	return corev1.Pod{ObjectMeta: meta(ns, name), Spec: spec}
}

// edgesOf returns the edges of type typ as "source -> target".
func edgesOf(edges []Edge, typ string) []string {
	var out []string
	for _, e := range edges {
		if e.EdgeType == typ {
			out = append(out, e.SourceUID+" -> "+e.TargetUID)
		}
	}
	slices.Sort(out)
	return out
}

func TestAttackEdges(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	web := map[string]string{"app": "web"}
	labeled := func(p corev1.Pod, l map[string]string) corev1.Pod { p.Labels = l; return p }
	secretVol := corev1.Volume{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db"}}}
	ingress := networkingv1.Ingress{ObjectMeta: meta("a", "ing"), Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
		IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{
			{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "internal"}}},
			{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "missing"}}},
		}}},
	}}}}
	node := corev1.Node{ObjectMeta: meta("", "n1")}
	role := func(ns, name string, rules ...rbacv1.PolicyRule) rbacv1.Role {
		return rbacv1.Role{ObjectMeta: meta(ns, name), Rules: rules}
	}
	bind := func(ns, name, roleName string) rbacv1.RoleBinding {
		return rbacv1.RoleBinding{ObjectMeta: meta(ns, name), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: roleName},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "robot"}}}
	}
	sas := []corev1.ServiceAccount{{ObjectMeta: meta("a", "robot")}, {ObjectMeta: meta("a", "other")}, {ObjectMeta: meta("a", "default")}}

	tests := []struct {
		name string
		snap inventory.Snapshot
		typ  string
		want []string
	}{
		{"LoadBalancer and NodePort are exposed, ClusterIP is not", inventory.Snapshot{
			Services: []corev1.Service{
				{ObjectMeta: meta("a", "lb"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: web}},
				nodePort("a", "np", web),
				{ObjectMeta: meta("a", "internal"), Spec: corev1.ServiceSpec{Selector: web}},
			}}, EdgeExposes, []string{"internet -> a/lb", "internet -> a/np"}},
		{"Ingress is exposed and routes to its backends", inventory.Snapshot{
			Ingresses: []networkingv1.Ingress{ingress},
			Services:  []corev1.Service{{ObjectMeta: meta("a", "internal"), Spec: corev1.ServiceSpec{Selector: web}}},
			Pods:      []corev1.Pod{labeled(corev1.Pod{ObjectMeta: meta("a", "web")}, web), {ObjectMeta: meta("a", "other")}},
		}, EdgeRoutesTo, []string{"a/ing -> a/internal", "a/internal -> a/web"}},
		{"Ingress edge from the Internet", inventory.Snapshot{Ingresses: []networkingv1.Ingress{ingress}}, EdgeExposes, []string{"internet -> a/ing"}},
		{"privileged, hostPID and a sensitive hostPath escape to the node", inventory.Snapshot{
			Nodes: []corev1.Node{node},
			Pods: []corev1.Pod{
				onNode("a", "priv", "n1", corev1.PodSpec{Containers: []corev1.Container{{Name: "c", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}),
				onNode("a", "pid", "n1", corev1.PodSpec{HostPID: true}),
				onNode("a", "sock", "n1", corev1.PodSpec{Volumes: []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}}}),
				onNode("a", "logs", "n1", corev1.PodSpec{Volumes: []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data/logs"}}}}}),
				onNode("a", "plain", "n1", corev1.PodSpec{}),
				onNode("a", "elsewhere", "gone", corev1.PodSpec{HostPID: true}),
			}}, EdgeEscapesToNode, []string{"a/pid -> /n1", "a/priv -> /n1", "a/sock -> /n1"}},
		{"node hosts its pods", inventory.Snapshot{
			Nodes: []corev1.Node{node},
			Pods:  []corev1.Pod{onNode("a", "p", "n1", corev1.PodSpec{}), onNode("a", "q", "", corev1.PodSpec{})},
		}, EdgeNodeHosts, []string{"/n1 -> a/p"}},
		{"token is mounted unless automount is off", inventory.Snapshot{
			ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: meta("a", "robot")}, {ObjectMeta: meta("a", "quiet"), AutomountServiceAccountToken: &no}},
			Pods: []corev1.Pod{
				{ObjectMeta: meta("a", "default-on"), Spec: corev1.PodSpec{ServiceAccountName: "robot"}},
				{ObjectMeta: meta("a", "pod-off"), Spec: corev1.PodSpec{ServiceAccountName: "robot", AutomountServiceAccountToken: &no}},
				{ObjectMeta: meta("a", "sa-off"), Spec: corev1.PodSpec{ServiceAccountName: "quiet"}},
				{ObjectMeta: meta("a", "pod-on"), Spec: corev1.PodSpec{ServiceAccountName: "quiet", AutomountServiceAccountToken: &yes}},
				{ObjectMeta: meta("a", "projected"), Spec: corev1.PodSpec{ServiceAccountName: "quiet", Volumes: []corev1.Volume{{Name: "t", VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "t"}}}}}}}}},
			}}, EdgeHasToken, []string{"a/default-on -> a/robot", "a/pod-on -> a/quiet", "a/projected -> a/quiet"}},
		{"get secrets in a namespace reads its Secrets", inventory.Snapshot{
			ServiceAccounts: sas,
			Pods:            []corev1.Pod{{ObjectMeta: meta("a", "p"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}}, {ObjectMeta: meta("b", "p"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}}},
			Roles: []rbacv1.Role{
				role("a", "reader", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}),
				role("a", "named", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"db"}}),
			},
			RoleBindings: []rbacv1.RoleBinding{bind("a", "rb", "reader"), bind("a", "rb-named", "named")},
		}, EdgeCanReadSecrets, []string{"a/robot -> secret:a/db"}},
		{"cluster-wide secret reading reaches every namespace", inventory.Snapshot{
			ServiceAccounts:     sas,
			Pods:                []corev1.Pod{{ObjectMeta: meta("a", "p"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}}, {ObjectMeta: meta("b", "p"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}}},
			ClusterRoles:        []rbacv1.ClusterRole{{ObjectMeta: meta("", "lister"), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}}}},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{ObjectMeta: meta("", "crb"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "lister"}, Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "a", Name: "robot"}}}},
		}, EdgeCanReadSecrets, []string{"a/robot -> secret:a/db", "a/robot -> secret:b/db"}},
		{"create deployments or pods/exec runs pods as other ServiceAccounts", inventory.Snapshot{
			ServiceAccounts: sas,
			Roles:           []rbacv1.Role{role("a", "deployer", rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}})},
			RoleBindings:    []rbacv1.RoleBinding{bind("a", "rb", "deployer")},
		}, EdgeCanCreateWorkloads, []string{"a/robot -> a/default", "a/robot -> a/other"}},
		{"pods/exec", inventory.Snapshot{
			ServiceAccounts: sas,
			Roles:           []rbacv1.Role{role("a", "exec", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}})},
			RoleBindings:    []rbacv1.RoleBinding{bind("a", "rb", "exec")},
		}, EdgeCanCreateWorkloads, []string{"a/robot -> a/default", "a/robot -> a/other"}},
		{"bind, impersonate and wildcards escalate; read-only does not", inventory.Snapshot{
			ServiceAccounts: sas,
			Roles: []rbacv1.Role{
				role("a", "binder", rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"bind"}}),
				role("a", "imp", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}}),
				role("a", "star", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}),
				role("a", "view", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}),
			},
			RoleBindings: []rbacv1.RoleBinding{bind("a", "rb-bind", "binder"), bind("a", "rb-imp", "imp"), bind("a", "rb-star", "star"), bind("a", "rb-view", "view")},
		}, EdgeCanEscalate, []string{"a/robot -> a/rb-bind", "a/robot -> a/rb-imp", "a/robot -> a/rb-star"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := edgesOf(AttackEdges(&tt.snap), tt.typ); !slices.Equal(got, tt.want) {
				t.Errorf("%s edges = %q, want %q", tt.typ, got, tt.want)
			}
		})
	}
}

func TestLateralEdges(t *testing.T) {
	t.Parallel()
	pod := func(ns, name, app string) corev1.Pod {
		p := corev1.Pod{ObjectMeta: meta(ns, name)}
		p.Labels = map[string]string{"app": app}
		return p
	}
	pods := []corev1.Pod{pod("a", "web", "web"), pod("a", "db", "db"), pod("b", "web", "web"), pod("b", "db", "db")}
	cves := []Edge{
		{SourceUID: "a/db", TargetUID: "a/db", EdgeType: EdgeHasCVE, Properties: map[string]string{"severity": "CRITICAL"}},
		{SourceUID: "b/db", TargetUID: "b/db", EdgeType: EdgeHasCVE, Properties: map[string]string{"severity": "HIGH"}},
		{SourceUID: "a/web", TargetUID: "a/web", EdgeType: EdgeHasCVE, Properties: map[string]string{"severity": "LOW"}},
	}
	deny := networkingv1.NetworkPolicy{ObjectMeta: meta("b", "deny"), Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
	egressOnly := networkingv1.NetworkPolicy{ObjectMeta: meta("a", "egress"), Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}}}
	tests := []struct {
		name     string
		policies []networkingv1.NetworkPolicy
		want     []string
	}{
		{"no policies: pods reach vulnerable pods of other workloads in their namespace", nil, []string{"a/web -> a/db", "b/web -> b/db"}},
		{"default-deny stops lateral movement", []networkingv1.NetworkPolicy{deny}, []string{"a/web -> a/db"}},
		{"an egress-only policy is no default-deny", []networkingv1.NetworkPolicy{egressOnly}, []string{"a/web -> a/db", "b/web -> b/db"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap := &inventory.Snapshot{Pods: pods, NetworkPolicies: tt.policies}
			if got := edgesOf(LateralEdges(snap, cves), EdgeCanReach); !slices.Equal(got, tt.want) {
				t.Errorf("CAN_REACH = %q, want %q", got, tt.want)
			}
		})
	}
}
