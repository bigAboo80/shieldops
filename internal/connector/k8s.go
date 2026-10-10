package connector

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/clientcmd"
)

// APITimeout bounds every single Kubernetes API call.
const APITimeout = 30 * time.Second

// Clients bundles the typed clientset with a metadata-only client.
// The metadata client lets the scanner list Secrets without pulling their data.
type Clients struct {
	Kube     kubernetes.Interface
	Metadata metadata.Interface
}

func NewClients(kubeconfigPath, kubeContext string) (*Clients, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	md, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create metadata client: %w", err)
	}
	return &Clients{Kube: kube, Metadata: md}, nil
}

func ListPods(ctx context.Context, cl kubernetes.Interface, ns string) ([]corev1.Pod, error) {
	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()
	pods, err := cl.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return pods.Items, nil
}

func ListServiceAccounts(ctx context.Context, cl kubernetes.Interface, ns string) ([]corev1.ServiceAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()
	sa, err := cl.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	return sa.Items, nil
}

func ListClusterRoleBindings(ctx context.Context, cl kubernetes.Interface) ([]rbacv1.ClusterRoleBinding, error) {
	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()
	crb, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list cluster role bindings: %w", err)
	}
	return crb.Items, nil
}

func ListServices(ctx context.Context, cl kubernetes.Interface, ns string) ([]corev1.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()
	svc, err := cl.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	return svc.Items, nil
}

// ListSecretsMetadata returns Secret metadata only; secret values never leave the API server.
func ListSecretsMetadata(ctx context.Context, md metadata.Interface, ns string) ([]metav1.PartialObjectMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, APITimeout)
	defer cancel()
	list, err := md.Resource(corev1.SchemeGroupVersion.WithResource("secrets")).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list secrets metadata: %w", err)
	}
	return list.Items, nil
}
