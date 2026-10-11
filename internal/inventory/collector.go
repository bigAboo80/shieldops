package inventory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/bigAboo80/shieldops/internal/connector"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
}

func Collect(ctx context.Context, cl kubernetes.Interface, ns string) (*Snapshot, error) {
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
	return &s, nil
}

func (s *Snapshot) Assets() []Asset {
	var assets []Asset
	secrets := map[string]bool{}
	for _, pod := range s.Pods {
		assets = append(assets, Asset{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, Labels: pod.Labels,
			UID: string(pod.UID), Images: PodImages(pod), Workload: Workload(pod)})
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
