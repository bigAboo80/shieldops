package graph

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Edges of attack paths: what an attacker who holds the source gets next.
const (
	EdgeExposes   = "EXPOSES"    // Internet -> Service (NodePort/LoadBalancer) or Ingress
	EdgeRoutesTo  = "ROUTES_TO"  // Ingress -> Service of its backends, Service -> Pod it selects
	EdgeRunsOn    = "RUNS_ON"    // Pod -> Node
	EdgeNodeHosts = "NODE_HOSTS" // Node -> Pod: a node gives access to every pod on it
	// Pod -> Node it can break out to; properties.reason: privileged, host_pid, host_path:<path>.
	EdgeEscapesToNode = "ESCAPES_TO_NODE"
	// Pod -> ServiceAccount whose token is mounted in it. USES_SA holds even
	// without a token; only HAS_TOKEN hands the rights to an attacker.
	EdgeHasToken = "HAS_TOKEN"
	// Effective RBAC rights of a ServiceAccount; properties: binding, role, scope (cluster|namespace).
	EdgeCanReadSecrets     = "CAN_READ_SECRETS"     // SA -> Secret it may get or list
	EdgeCanCreateWorkloads = "CAN_CREATE_WORKLOADS" // SA -> SA it may run a pod as (create pods/workloads, pods/exec)
	EdgeCanEscalate        = "CAN_ESCALATE"         // SA -> binding granting bind/escalate/impersonate or "*"
	// Pod -> Pod with a CRITICAL/HIGH CVE in the same namespace, when no
	// default-deny NetworkPolicy stops the traffic.
	EdgeCanReach = "CAN_REACH"
)

// AttackEdges derives the edges of attack paths from the snapshot. They are
// apart from BuildEdges: the edges detectors query stay as they were.
func AttackEdges(s *inventory.Snapshot) []Edge {
	saUIDs := map[string]string{}
	for _, sa := range s.ServiceAccounts {
		saUIDs[sa.Namespace+"/"+sa.Name] = string(sa.UID)
	}
	var edges []Edge
	internet := s.InternetFacing()

	services := map[string]corev1.Service{}
	for _, svc := range s.Services {
		services[svc.Namespace+"/"+svc.Name] = svc
		if internet && inventory.Exposed(svc) {
			edges = append(edges, Edge{SourceUID: inventory.InternetUID, TargetUID: string(svc.UID), EdgeType: EdgeExposes})
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		for _, pod := range s.Pods {
			if pod.Namespace == svc.Namespace && sel.Matches(labels.Set(pod.Labels)) {
				edges = append(edges, Edge{SourceUID: string(svc.UID), TargetUID: string(pod.UID), EdgeType: EdgeRoutesTo})
			}
		}
	}
	for _, ing := range s.Ingresses {
		edges = append(edges, Edge{SourceUID: inventory.InternetUID, TargetUID: string(ing.UID), EdgeType: EdgeExposes})
		for _, name := range ingressBackends(ing) {
			if svc, ok := services[ing.Namespace+"/"+name]; ok {
				edges = append(edges, Edge{SourceUID: string(ing.UID), TargetUID: string(svc.UID), EdgeType: EdgeRoutesTo})
			}
		}
	}

	nodes := map[string]string{}
	for _, n := range s.Nodes {
		nodes[n.Name] = string(n.UID)
	}
	automount := map[string]bool{}
	for _, sa := range s.ServiceAccounts {
		automount[sa.Namespace+"/"+sa.Name] = sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken
	}
	for _, pod := range s.Pods {
		uid := string(pod.UID)
		if node, ok := nodes[pod.Spec.NodeName]; ok {
			edges = append(edges,
				Edge{SourceUID: uid, TargetUID: node, EdgeType: EdgeRunsOn},
				Edge{SourceUID: node, TargetUID: uid, EdgeType: EdgeNodeHosts})
			if reasons := escapeReasons(pod); reasons != "" {
				edges = append(edges, Edge{SourceUID: uid, TargetUID: node, EdgeType: EdgeEscapesToNode, Properties: map[string]string{"reason": reasons}})
			}
		}
		saName := cmp.Or(pod.Spec.ServiceAccountName, "default")
		key := pod.Namespace + "/" + saName
		if sa, ok := saUIDs[key]; ok && hasToken(pod, automount[key]) {
			edges = append(edges, Edge{SourceUID: uid, TargetUID: sa, EdgeType: EdgeHasToken})
		}
	}
	return append(edges, rbacEdges(s, saUIDs)...)
}

// ingressBackends lists the Services an Ingress routes to.
func ingressBackends(ing networkingv1.Ingress) []string {
	var names []string
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		names = append(names, b.Service.Name)
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				names = append(names, p.Backend.Service.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// escapeReasons names what lets a pod break out to its node: a privileged
// container, the node's PID namespace or a sensitive hostPath.
func escapeReasons(pod corev1.Pod) string {
	var reasons []string
	for _, f := range inventory.PodFacts(pod) {
		switch {
		case f.Kind == inventory.FactPrivileged && !slices.Contains(reasons, "privileged"):
			reasons = append(reasons, "privileged")
		case f.Kind == inventory.FactHostPID:
			reasons = append(reasons, "host_pid")
		case f.Kind == inventory.FactHostPath && inventory.SensitiveHostPath(f.Value):
			reasons = append(reasons, "host_path:"+f.Value)
		}
	}
	slices.Sort(reasons)
	return strings.Join(reasons, ",")
}

// hasToken: the pod's ServiceAccount token is mounted, by automount (the pod
// setting wins over the ServiceAccount's) or by a projected token volume.
func hasToken(pod corev1.Pod, saAutomount bool) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken != nil {
				return true
			}
		}
	}
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	return saAutomount
}

// rights are what an attacker can do with the rules of a role.
type rights struct{ readSecrets, createWorkloads, escalate bool }

// workloadResources: creating any of them runs a pod with a chosen ServiceAccount.
var workloadResources = map[string][]string{
	"":      {"pods"},
	"apps":  {"deployments", "daemonsets", "statefulsets", "replicasets"},
	"batch": {"jobs", "cronjobs"},
}

func rightsOf(rules []rbacv1.PolicyRule) rights {
	var r rights
	for _, rule := range rules {
		if slices.Contains(rule.Verbs, rbacv1.VerbAll) || slices.Contains(rule.Resources, rbacv1.ResourceAll) ||
			slices.ContainsFunc(rule.Verbs, func(v string) bool { return v == "bind" || v == "escalate" || v == "impersonate" }) {
			r.escalate = true
		}
		if allows(rule, "", "secrets", "get", "list") {
			r.readSecrets = true
		}
		if allows(rule, "", "pods/exec", "create") {
			r.createWorkloads = true
		}
		for group, resources := range workloadResources {
			for _, res := range resources {
				if allows(rule, group, res, "create") {
					r.createWorkloads = true
				}
			}
		}
	}
	return r
}

// allows tells whether rule grants one of verbs on resource of group.
// Rules restricted to resourceNames do not count: they name single objects.
func allows(rule rbacv1.PolicyRule, group, resource string, verbs ...string) bool {
	if len(rule.ResourceNames) > 0 {
		return false
	}
	has := func(list []string, want ...string) bool {
		return slices.ContainsFunc(list, func(v string) bool { return v == "*" || slices.Contains(want, v) })
	}
	return has(rule.APIGroups, group) && has(rule.Resources, resource) && has(rule.Verbs, verbs...)
}

// rbacEdges turns the rights of every binding into edges from its
// ServiceAccounts: to the Secrets they can read, the ServiceAccounts they
// can run pods as, and to the binding itself when it lets them escalate.
func rbacEdges(s *inventory.Snapshot, saUIDs map[string]string) []Edge {
	clusterRoles := map[string][]rbacv1.PolicyRule{}
	for _, r := range s.ClusterRoles {
		clusterRoles[r.Name] = r.Rules
	}
	roles := map[string][]rbacv1.PolicyRule{}
	for _, r := range s.Roles {
		roles[r.Namespace+"/"+r.Name] = r.Rules
	}
	// Secrets are known by pod references only.
	secrets := map[string][]string{} // namespace -> Secret UIDs
	for _, pod := range s.Pods {
		for _, name := range inventory.PodSecretNames(pod) {
			if uid := inventory.SecretUID(pod.Namespace, name); !slices.Contains(secrets[pod.Namespace], uid) {
				secrets[pod.Namespace] = append(secrets[pod.Namespace], uid)
			}
		}
	}
	sas := map[string][]string{} // namespace -> ServiceAccount UIDs
	for _, sa := range s.ServiceAccounts {
		sas[sa.Namespace] = append(sas[sa.Namespace], string(sa.UID))
	}
	inScope := func(m map[string][]string, ns string) []string {
		if ns != "" {
			return m[ns]
		}
		var all []string
		for _, k := range slices.Sorted(maps.Keys(m)) {
			all = append(all, m[k]...)
		}
		return all
	}

	var edges []Edge
	link := func(bindingUID, ns string, ref rbacv1.RoleRef, rules []rbacv1.PolicyRule, subjects []rbacv1.Subject) {
		r := rightsOf(rules)
		if r == (rights{}) {
			return
		}
		scope := "cluster"
		if ns != "" {
			scope = "namespace"
		}
		props := map[string]string{"role": ref.Name, "scope": scope}
		for _, subj := range subjects {
			if subj.Kind != rbacv1.ServiceAccountKind {
				continue
			}
			sa, ok := saUIDs[cmp.Or(subj.Namespace, ns)+"/"+subj.Name]
			if !ok {
				continue
			}
			if r.escalate {
				edges = append(edges, Edge{SourceUID: sa, TargetUID: bindingUID, EdgeType: EdgeCanEscalate, Properties: props})
			}
			if r.readSecrets {
				for _, uid := range inScope(secrets, ns) {
					edges = append(edges, Edge{SourceUID: sa, TargetUID: uid, EdgeType: EdgeCanReadSecrets, Properties: props})
				}
			}
			if r.createWorkloads {
				for _, uid := range inScope(sas, ns) {
					if uid != sa {
						edges = append(edges, Edge{SourceUID: sa, TargetUID: uid, EdgeType: EdgeCanCreateWorkloads, Properties: props})
					}
				}
			}
		}
	}
	for _, crb := range s.ClusterRoleBindings {
		if crb.RoleRef.Kind == "ClusterRole" {
			link(string(crb.UID), "", crb.RoleRef, clusterRoles[crb.RoleRef.Name], crb.Subjects)
		}
	}
	for _, rb := range s.RoleBindings {
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			link(string(rb.UID), rb.Namespace, rb.RoleRef, clusterRoles[rb.RoleRef.Name], rb.Subjects)
		case "Role":
			link(string(rb.UID), rb.Namespace, rb.RoleRef, roles[rb.Namespace+"/"+rb.RoleRef.Name], rb.Subjects)
		}
	}
	return edges
}

// LateralEdges links pods to the pods of other workloads in their namespace
// that have a CRITICAL or HIGH CVE: an attacker inside a pod can exploit
// them. A default-deny NetworkPolicy in the namespace stops this; other
// policies are not analysed.
func LateralEdges(s *inventory.Snapshot, cves []Edge) []Edge {
	vulnerable := map[string]bool{}
	for _, e := range cves {
		if e.EdgeType == EdgeHasCVE && (e.Properties["severity"] == "CRITICAL" || e.Properties["severity"] == "HIGH") {
			vulnerable[e.SourceUID] = true
		}
	}
	denied := map[string]bool{}
	for _, np := range s.NetworkPolicies {
		if defaultDeny(np) {
			denied[np.Namespace] = true
		}
	}
	var edges []Edge
	for _, b := range s.Pods {
		if !vulnerable[string(b.UID)] || denied[b.Namespace] {
			continue
		}
		for _, a := range s.Pods {
			if a.Namespace == b.Namespace && inventory.Workload(a) != inventory.Workload(b) {
				edges = append(edges, Edge{SourceUID: string(a.UID), TargetUID: string(b.UID), EdgeType: EdgeCanReach})
			}
		}
	}
	return edges
}

// defaultDeny: the policy selects every pod of its namespace and allows no
// ingress traffic.
func defaultDeny(np networkingv1.NetworkPolicy) bool {
	sel := np.Spec.PodSelector
	if len(sel.MatchLabels) > 0 || len(sel.MatchExpressions) > 0 || len(np.Spec.Ingress) > 0 {
		return false
	}
	// Without policyTypes a policy restricts ingress.
	return len(np.Spec.PolicyTypes) == 0 || slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
}
