package inventory

import (
	"context"
	"fmt"

	"github.com/shieldops/core/internal/connector"
	"k8s.io/client-go/kubernetes"
)

type Asset struct {
	Kind      string
	Name      string
	Namespace string
	Labels    map[string]string
	UID       string
}

func CollectAll(ctx context.Context, cl *kubernetes.Clientset, ns string) ([]Asset, error) {
	var assets []Asset

	pods, err := connector.ListPods(ctx, cl, ns)
	if err != nil {
		return nil, fmt.Errorf("collect pods: %w", err)
	}
	for _, pod := range pods {
		podLabels := make(map[string]string)
		for k, v := range pod.Labels { podLabels[k] = v }
		if len(pod.Spec.Containers) > 0 {
			podLabels["image"] = pod.Spec.Containers[0].Image
		}
		assets = append(assets, Asset{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, Labels: podLabels, UID: string(pod.UID)})
	}

	sas, err := connector.ListServiceAccounts(ctx, cl, ns)
	if err != nil {
		return nil, fmt.Errorf("collect service accounts: %w", err)
	}
	for _, sa := range sas {
		assets = append(assets, Asset{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace, Labels: sa.Labels, UID: string(sa.UID)})
	}

	crbs, err := connector.ListClusterRoleBindings(ctx, cl)
	if err != nil {
		return nil, fmt.Errorf("collect cluster role bindings: %w", err)
	}
	for _, crb := range crbs {
		assets = append(assets, Asset{Kind: "ClusterRoleBinding", Name: crb.Name, Namespace: "", Labels: crb.Labels, UID: string(crb.UID)})
	}

	svcs, err := connector.ListServices(ctx, cl, ns)
	if err != nil {
		return nil, fmt.Errorf("collect services: %w", err)
	}
	for _, svc := range svcs {
		assets = append(assets, Asset{Kind: "Service", Name: svc.Name, Namespace: svc.Namespace, Labels: svc.Labels, UID: string(svc.UID)})
	}

	secrets, err := connector.ListSecrets(ctx, cl, ns)
	if err != nil {
		return nil, fmt.Errorf("collect secrets: %w", err)
	}
	for _, secret := range secrets {
		assets = append(assets, Asset{Kind: "Secret", Name: secret.Name, Namespace: secret.Namespace, Labels: secret.Labels, UID: string(secret.UID)})
	}

	return assets, nil
}
