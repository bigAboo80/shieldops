package connector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return clientset, nil
}

func ListPods(ctx context.Context, cl *kubernetes.Clientset, ns string) ([]corev1.Pod, error) {
	pods, err := cl.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return pods.Items, nil
}

func ListServiceAccounts(ctx context.Context, cl *kubernetes.Clientset, ns string) ([]corev1.ServiceAccount, error) {
	sa, err := cl.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	return sa.Items, nil
}

func ListClusterRoleBindings(ctx context.Context, cl *kubernetes.Clientset) ([]rbacv1.ClusterRoleBinding, error) {
	crb, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list cluster role bindings: %w", err)
	}
	return crb.Items, nil
}

func ListServices(ctx context.Context, cl *kubernetes.Clientset, ns string) ([]corev1.Service, error) {
	svc, err := cl.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	return svc.Items, nil
}

func ListSecrets(ctx context.Context, cl *kubernetes.Clientset, ns string) ([]corev1.Secret, error) {
	secrets, err := cl.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	return secrets.Items, nil
}
