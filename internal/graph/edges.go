package graph

import (
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	EdgeUsesSA       = "USES_SA"       // Pod -> ServiceAccount
	EdgeBoundToRole  = "BOUND_TO_ROLE" // ServiceAccount -> ClusterRoleBinding, properties.role = ClusterRole name
	EdgeMountsSecret = "MOUNTS_SECRET" // Pod -> Secret
	EdgeExposedVia   = "EXPOSED_VIA"   // Pod -> Service (NodePort/LoadBalancer)
	EdgeHasCVE       = "HAS_CVE"       // Pod -> Pod, properties describe the CVE
)

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
	return edges
}
