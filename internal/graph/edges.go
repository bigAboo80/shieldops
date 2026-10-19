package graph

import (
	"slices"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	EdgeUsesSA       = "USES_SA"       // Pod -> ServiceAccount
	EdgeBoundToRole  = "BOUND_TO_ROLE" // ServiceAccount -> ClusterRoleBinding, properties.role = ClusterRole name
	EdgeMountsSecret = "MOUNTS_SECRET" // Pod -> Secret
	EdgeExposedVia   = "EXPOSED_VIA"   // Pod -> Service (NodePort/LoadBalancer)
	EdgeHasCVE       = "HAS_CVE"       // Pod -> Pod, properties describe the CVE
	// Pod -> NetworkPolicy that selects it.
	EdgeSelectedBy = "SELECTED_BY"
	// ServiceAccount -> ClusterRoleBinding/RoleBinding whose role has a "*" rule;
	// properties: role, role_kind (ClusterRole|Role), scope (cluster|namespace), wildcard (e.g. "verbs,resources").
	EdgeWildcardRole = "WILDCARD_ROLE"
)

// clusterAdmin is covered by the cluster-admin-sa detector, so a cluster-wide
// binding to it is not reported again as a wildcard role.
const clusterAdmin = "cluster-admin"

// BuildEdges derives graph edges from a scan snapshot. Edges only point at
// objects present in the snapshot, so every endpoint exists in the assets table.
func BuildEdges(s *inventory.Snapshot) []Edge {
	saUIDs := map[string]string{}
	for _, sa := range s.ServiceAccounts {
		saUIDs[sa.Namespace+"/"+sa.Name] = string(sa.UID)
	}

	var edges []Edge
	for _, pod := range s.Pods {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		if uid, ok := saUIDs[pod.Namespace+"/"+saName]; ok {
			edges = append(edges, Edge{SourceUID: string(pod.UID), TargetUID: uid, EdgeType: EdgeUsesSA})
		}
		for _, name := range inventory.PodSecretNames(pod) {
			edges = append(edges, Edge{SourceUID: string(pod.UID), TargetUID: inventory.SecretUID(pod.Namespace, name), EdgeType: EdgeMountsSecret})
		}
	}

	for _, crb := range s.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" {
			continue
		}
		for _, subj := range crb.Subjects {
			if subj.Kind != rbacv1.ServiceAccountKind {
				continue
			}
			if uid, ok := saUIDs[subj.Namespace+"/"+subj.Name]; ok {
				edges = append(edges, Edge{SourceUID: uid, TargetUID: string(crb.UID), EdgeType: EdgeBoundToRole,
					Properties: map[string]string{"role": crb.RoleRef.Name}})
			}
		}
	}

	for _, svc := range s.Services {
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		// An empty selector matches nothing: such services point at manual Endpoints.
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		for _, pod := range s.Pods {
			if pod.Namespace == svc.Namespace && sel.Matches(labels.Set(pod.Labels)) {
				edges = append(edges, Edge{SourceUID: string(pod.UID), TargetUID: string(svc.UID), EdgeType: EdgeExposedVia})
			}
		}
	}

	edges = append(edges, networkPolicyEdges(s)...)
	edges = append(edges, wildcardEdges(s, saUIDs)...)
	return edges
}

func networkPolicyEdges(s *inventory.Snapshot) []Edge {
	var edges []Edge
	for _, np := range s.NetworkPolicies {
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil { // an invalid selector selects nothing
			continue
		}
		for _, pod := range s.Pods {
			if pod.Namespace == np.Namespace && sel.Matches(labels.Set(pod.Labels)) {
				edges = append(edges, Edge{SourceUID: string(pod.UID), TargetUID: string(np.UID), EdgeType: EdgeSelectedBy})
			}
		}
	}
	return edges
}

// wildcardEdges links ServiceAccounts to bindings whose role grants "*" in
// verbs, resources or apiGroups.
func wildcardEdges(s *inventory.Snapshot, saUIDs map[string]string) []Edge {
	clusterRoles := map[string][]rbacv1.PolicyRule{}
	for _, r := range s.ClusterRoles {
		clusterRoles[r.Name] = r.Rules
	}
	roles := map[string][]rbacv1.PolicyRule{}
	for _, r := range s.Roles {
		roles[r.Namespace+"/"+r.Name] = r.Rules
	}

	var edges []Edge
	link := func(bindingUID, scope string, ref rbacv1.RoleRef, rules []rbacv1.PolicyRule, subjects []rbacv1.Subject, defaultNS string) {
		wildcard := wildcardFields(rules)
		if wildcard == "" {
			return
		}
		for _, subj := range subjects {
			if subj.Kind != rbacv1.ServiceAccountKind {
				continue
			}
			ns := subj.Namespace
			if ns == "" {
				ns = defaultNS
			}
			if uid, ok := saUIDs[ns+"/"+subj.Name]; ok {
				edges = append(edges, Edge{SourceUID: uid, TargetUID: bindingUID, EdgeType: EdgeWildcardRole,
					Properties: map[string]string{"role": ref.Name, "role_kind": ref.Kind, "scope": scope, "wildcard": wildcard}})
			}
		}
	}
	for _, crb := range s.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name == clusterAdmin {
			continue
		}
		link(string(crb.UID), "cluster", crb.RoleRef, clusterRoles[crb.RoleRef.Name], crb.Subjects, "")
	}
	for _, rb := range s.RoleBindings {
		var rules []rbacv1.PolicyRule
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			rules = clusterRoles[rb.RoleRef.Name]
		case "Role":
			rules = roles[rb.Namespace+"/"+rb.RoleRef.Name]
		default:
			continue
		}
		link(string(rb.UID), "namespace", rb.RoleRef, rules, rb.Subjects, rb.Namespace)
	}
	return edges
}

// wildcardFields names the rule fields that contain "*", e.g. "verbs,resources".
func wildcardFields(rules []rbacv1.PolicyRule) string {
	var fields []string
	for _, r := range rules {
		if slices.Contains(r.Verbs, rbacv1.VerbAll) && !slices.Contains(fields, "verbs") {
			fields = append(fields, "verbs")
		}
		if slices.Contains(r.Resources, rbacv1.ResourceAll) && !slices.Contains(fields, "resources") {
			fields = append(fields, "resources")
		}
		if slices.Contains(r.APIGroups, rbacv1.APIGroupAll) && !slices.Contains(fields, "apiGroups") {
			fields = append(fields, "apiGroups")
		}
	}
	slices.Sort(fields)
	return strings.Join(fields, ",")
}
