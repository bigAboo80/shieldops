package inventory

import (
	"context"
	"fmt"
	"slices"

	"github.com/bigAboo80/shieldops/internal/connector"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Asset struct {
	Kind      string
	Name      string
	Namespace string
	Labels    map[string]string
	UID       string
	Images    []string
}

// Snapshot holds the raw cluster objects of one scan, so edges are built
// from the same state as assets without listing the API twice.
type Snapshot struct {
	Pods                []corev1.Pod
	ServiceAccounts     []corev1.ServiceAccount
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	Services            []corev1.Service
	Secrets             []metav1.PartialObjectMetadata
}

func Collect(ctx context.Context, cl *connector.Clients, ns string) (*Snapshot, error) {
	var s Snapshot
	var err error
	if s.Pods, err = connector.ListPods(ctx, cl.Kube, ns); err != nil {
		return nil, fmt.Errorf("collect pods: %w", err)
	}
	if s.ServiceAccounts, err = connector.ListServiceAccounts(ctx, cl.Kube, ns); err != nil {
		return nil, fmt.Errorf("collect service accounts: %w", err)
	}
	if s.ClusterRoleBindings, err = connector.ListClusterRoleBindings(ctx, cl.Kube); err != nil {
		return nil, fmt.Errorf("collect cluster role bindings: %w", err)
	}
	if s.Services, err = connector.ListServices(ctx, cl.Kube, ns); err != nil {
		return nil, fmt.Errorf("collect services: %w", err)
	}
	if s.Secrets, err = connector.ListSecretsMetadata(ctx, cl.Metadata, ns); err != nil {
		return nil, fmt.Errorf("collect secrets: %w", err)
	}
	return &s, nil
}

func (s *Snapshot) Assets() []Asset {
	var assets []Asset
	for _, pod := range s.Pods {
		assets = append(assets, Asset{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, Labels: pod.Labels, UID: string(pod.UID), Images: PodImages(pod)})
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
	for _, secret := range s.Secrets {
		assets = append(assets, Asset{Kind: "Secret", Name: secret.Name, Namespace: secret.Namespace, Labels: secret.Labels, UID: string(secret.UID)})
	}
	return assets
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
