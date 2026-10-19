package inventory

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/bigAboo80/shieldops/internal/connector"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Asset struct {
	Kind      string
	Name      string
	Namespace string
	Labels    map[string]string
	UID       string
	Images    []string
	// Workload is the pod's owning controller, e.g. "Deployment/web"; empty for non-pods.
	Workload string
	// Facts are security-relevant properties of the object, stored in their own table.
	Facts []Fact
}

// Fact kinds of a pod. Detectors select assets by kind, value is the detail.
const (
	FactPrivileged  = "privileged"   // value: container with privileged or SYS_ADMIN
	FactHostNetwork = "host_network" // value: "true"
	FactHostPID     = "host_pid"     // value: "true"
	FactHostIPC     = "host_ipc"     // value: "true"
	FactHostPath    = "host_path"    // value: path on the node
	FactLatestImage = "latest_image" // value: image without a tag, or tagged latest, and no digest
	FactStaticPod   = "static_pod"   // value: "true"; a pod the kubelet runs from a file, owned by its node
)

type Fact struct {
	Kind  string
	Value string
}

// Snapshot holds the raw cluster objects of one scan, so edges are built
// from the same state as assets without listing the API twice.
//
// Secrets are deliberately not listed: RBAC cannot grant "metadata only",
// and a token allowed to list Secrets can read their values. Secret nodes
// are derived from pod references instead.
type Snapshot struct {
	Pods                []corev1.Pod
	ServiceAccounts     []corev1.ServiceAccount
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	Services            []corev1.Service
	NetworkPolicies     []networkingv1.NetworkPolicy
	RoleBindings        []rbacv1.RoleBinding
	// Roles and ClusterRoles only feed edges: bindings are the graph nodes.
	Roles        []rbacv1.Role
	ClusterRoles []rbacv1.ClusterRole
	Ingresses    []networkingv1.Ingress
	Nodes        []corev1.Node
}

// InternetUID is the node of the Internet: the entry of attack paths. It is
// an asset only when something is exposed to it.
const InternetUID = "internet"

// Collect lists the cluster; ns limits namespaced objects to one namespace
// (empty = all) and exclude drops the listed namespaces.
func Collect(ctx context.Context, cl kubernetes.Interface, ns string, exclude []string) (*Snapshot, error) {
	var s Snapshot
	var err error
	if s.Pods, err = connector.ListPods(ctx, cl, ns); err != nil {
		return nil, fmt.Errorf("collect pods: %w", err)
	}
	if s.ServiceAccounts, err = connector.ListServiceAccounts(ctx, cl, ns); err != nil {
		return nil, fmt.Errorf("collect service accounts: %w", err)
	}
	if s.ClusterRoleBindings, err = connector.ListClusterRoleBindings(ctx, cl); err != nil {
		return nil, fmt.Errorf("collect cluster role bindings: %w", err)
	}
	if s.Services, err = connector.ListServices(ctx, cl, ns); err != nil {
		return nil, fmt.Errorf("collect services: %w", err)
	}
	if s.NetworkPolicies, err = optional(connector.ListNetworkPolicies(ctx, cl, ns)); err != nil {
		return nil, fmt.Errorf("collect network policies: %w", err)
	}
	if s.RoleBindings, err = optional(connector.ListRoleBindings(ctx, cl, ns)); err != nil {
		return nil, fmt.Errorf("collect role bindings: %w", err)
	}
	if s.Roles, err = optional(connector.ListRoles(ctx, cl, ns)); err != nil {
		return nil, fmt.Errorf("collect roles: %w", err)
	}
	if s.ClusterRoles, err = optional(connector.ListClusterRoles(ctx, cl)); err != nil {
		return nil, fmt.Errorf("collect cluster roles: %w", err)
	}
	if s.Ingresses, err = optional(connector.ListIngresses(ctx, cl, ns)); err != nil {
		return nil, fmt.Errorf("collect ingresses: %w", err)
	}
	if s.Nodes, err = optional(connector.ListNodes(ctx, cl)); err != nil {
		return nil, fmt.Errorf("collect nodes: %w", err)
	}
	s.exclude(exclude)
	return &s, nil
}

// optional skips an API that does not exist on the server (NotFound);
// every other error is returned.
func optional[T any](items []T, err error) ([]T, error) {
	if apierrors.IsNotFound(err) {
		fmt.Fprintf(os.Stderr, "skipping: %v\n", err)
		return nil, nil
	}
	return items, err
}

// exclude drops namespaced objects of the given namespaces. Cluster-scoped
// objects stay: bindings of an excluded ServiceAccount are harmless without it.
func (s *Snapshot) exclude(namespaces []string) {
	if len(namespaces) == 0 {
		return
	}
	skip := func(ns string) bool { return slices.Contains(namespaces, ns) }
	s.Pods = slices.DeleteFunc(s.Pods, func(o corev1.Pod) bool { return skip(o.Namespace) })
	s.ServiceAccounts = slices.DeleteFunc(s.ServiceAccounts, func(o corev1.ServiceAccount) bool { return skip(o.Namespace) })
	s.Services = slices.DeleteFunc(s.Services, func(o corev1.Service) bool { return skip(o.Namespace) })
	s.NetworkPolicies = slices.DeleteFunc(s.NetworkPolicies, func(o networkingv1.NetworkPolicy) bool { return skip(o.Namespace) })
	s.RoleBindings = slices.DeleteFunc(s.RoleBindings, func(o rbacv1.RoleBinding) bool { return skip(o.Namespace) })
	s.Roles = slices.DeleteFunc(s.Roles, func(o rbacv1.Role) bool { return skip(o.Namespace) })
	s.Ingresses = slices.DeleteFunc(s.Ingresses, func(o networkingv1.Ingress) bool { return skip(o.Namespace) })
}

// Exposed tells whether a Service is reachable from outside the cluster.
func Exposed(svc corev1.Service) bool {
	return svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort
}

// InternetFacing: some Service or Ingress is reachable from outside.
func (s *Snapshot) InternetFacing() bool {
	return len(s.Ingresses) > 0 || slices.ContainsFunc(s.Services, Exposed)
}

func (s *Snapshot) Assets() []Asset {
	var assets []Asset
	secrets := map[string]bool{}
	for _, pod := range s.Pods {
		assets = append(assets, Asset{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, Labels: pod.Labels,
			UID: string(pod.UID), Images: PodImages(pod), Workload: Workload(pod), Facts: PodFacts(pod)})
		for _, name := range PodSecretNames(pod) {
			uid := SecretUID(pod.Namespace, name)
			if !secrets[uid] {
				secrets[uid] = true
				assets = append(assets, Asset{Kind: "Secret", Name: name, Namespace: pod.Namespace, UID: uid})
			}
		}
	}
	for _, sa := range s.ServiceAccounts {
		assets = append(assets, Asset{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace, Labels: sa.Labels, UID: string(sa.UID)})
	}
	for _, crb := range s.ClusterRoleBindings {
		assets = append(assets, Asset{Kind: "ClusterRoleBinding", Name: crb.Name, Labels: crb.Labels, UID: string(crb.UID)})
	}
	for _, svc := range s.Services {
		assets = append(assets, Asset{Kind: "Service", Name: svc.Name, Namespace: svc.Namespace, Labels: svc.Labels, UID: string(svc.UID)})
	}
	for _, np := range s.NetworkPolicies {
		assets = append(assets, Asset{Kind: "NetworkPolicy", Name: np.Name, Namespace: np.Namespace, Labels: np.Labels, UID: string(np.UID)})
	}
	for _, rb := range s.RoleBindings {
		assets = append(assets, Asset{Kind: "RoleBinding", Name: rb.Name, Namespace: rb.Namespace, Labels: rb.Labels, UID: string(rb.UID)})
	}
	for _, ing := range s.Ingresses {
		assets = append(assets, Asset{Kind: "Ingress", Name: ing.Name, Namespace: ing.Namespace, Labels: ing.Labels, UID: string(ing.UID)})
	}
	for _, n := range s.Nodes {
		assets = append(assets, Asset{Kind: "Node", Name: n.Name, Labels: n.Labels, UID: string(n.UID)})
	}
	if s.InternetFacing() {
		assets = append(assets, Asset{Kind: "Internet", Name: "Internet", UID: InternetUID})
	}
	return assets
}

// PodsByImage maps every image to the UIDs of pods running it.
func (s *Snapshot) PodsByImage() map[string][]string {
	res := map[string][]string{}
	for _, pod := range s.Pods {
		for _, image := range PodImages(pod) {
			res[image] = append(res[image], string(pod.UID))
		}
	}
	return res
}

// SecretUID identifies a Secret node by reference, since Secret objects are never read.
func SecretUID(ns, name string) string {
	return "secret:" + ns + "/" + name
}

// Workload names the controller that owns the pod, so findings survive pod
// restarts and rollouts: "Deployment/web", "StatefulSet/db" or "Pod/name".
func Workload(pod corev1.Pod) string {
	ref := metav1.GetControllerOf(&pod)
	if ref == nil || ref.Kind == "Node" { // static pods are owned by their node
		return "Pod/" + pod.Name
	}
	if ref.Kind == "ReplicaSet" {
		if hash := pod.Labels["pod-template-hash"]; hash != "" {
			if deploy, ok := strings.CutSuffix(ref.Name, "-"+hash); ok {
				return "Deployment/" + deploy
			}
		}
	}
	return ref.Kind + "/" + ref.Name
}

// PodImages returns unique images of all init and regular containers.
func PodImages(pod corev1.Pod) []string {
	var images []string
	seen := map[string]bool{}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			images = append(images, c.Image)
		}
	}
	return images
}

// PodSecretNames lists unique Secrets a pod consumes via volumes, projected
// volumes, envFrom and env valueFrom in init and regular containers.
func PodSecretNames(pod corev1.Pod) []string {
	var names []string
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil {
			names = append(names, v.Secret.SecretName)
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					names = append(names, src.Secret.Name)
				}
			}
		}
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				names = append(names, ef.SecretRef.Name)
			}
		}
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				names = append(names, env.ValueFrom.SecretKeyRef.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// PodFacts extracts the security-relevant settings of a pod, sorted and unique.
func PodFacts(pod corev1.Pod) []Fact {
	var facts []Fact
	if ref := metav1.GetControllerOf(&pod); ref != nil && ref.Kind == "Node" {
		facts = append(facts, Fact{FactStaticPod, "true"})
	}
	if pod.Spec.HostNetwork {
		facts = append(facts, Fact{FactHostNetwork, "true"})
	}
	if pod.Spec.HostPID {
		facts = append(facts, Fact{FactHostPID, "true"})
	}
	if pod.Spec.HostIPC {
		facts = append(facts, Fact{FactHostIPC, "true"})
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			facts = append(facts, Fact{FactHostPath, v.HostPath.Path})
		}
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if isPrivileged(c.SecurityContext) {
			facts = append(facts, Fact{FactPrivileged, c.Name})
		}
		if isFloatingImage(c.Image) {
			facts = append(facts, Fact{FactLatestImage, c.Image})
		}
	}
	slices.SortFunc(facts, func(a, b Fact) int {
		return strings.Compare(a.Kind+"\x00"+a.Value, b.Kind+"\x00"+b.Value)
	})
	return slices.Compact(facts)
}

// sensitiveHostPaths give control over the node or the container runtime;
// everything below them counts too. "/" is matched exactly.
var sensitiveHostPaths = []string{
	"/etc",
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd",
	"/var/run/containerd",
	"/run/crio",
	"/var/run/crio",
	"/run/cri-dockerd.sock",
	"/var/run/cri-dockerd.sock",
	"/var/lib/kubelet",
	// k3s and RKE2: the runtime socket, and the data with the cluster's tokens.
	"/run/k3s",
	"/var/lib/rancher",
	"/var/snap/microk8s",
}

// SensitiveHostPath tells whether mounting the node path p gives control
// over the node.
func SensitiveHostPath(p string) bool {
	p = path.Clean(p)
	if p == "/" {
		return true
	}
	for _, s := range sensitiveHostPaths {
		if p == s || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
}

// isPrivileged: privileged mode, or privilege escalation together with SYS_ADMIN.
func isPrivileged(sc *corev1.SecurityContext) bool {
	if sc == nil {
		return false
	}
	if sc.Privileged != nil && *sc.Privileged {
		return true
	}
	if sc.AllowPrivilegeEscalation == nil || !*sc.AllowPrivilegeEscalation || sc.Capabilities == nil {
		return false
	}
	return slices.Contains(sc.Capabilities.Add, "SYS_ADMIN")
}

// isFloatingImage: no digest, and either no tag or the tag latest.
func isFloatingImage(image string) bool {
	if image == "" || strings.Contains(image, "@") {
		return false
	}
	name := image[strings.LastIndex(image, "/")+1:] // a registry port is not a tag
	tag, hasTag := strings.CutPrefix(name[strings.IndexByte(name+":", ':'):], ":")
	return !hasTag || tag == "latest"
}
