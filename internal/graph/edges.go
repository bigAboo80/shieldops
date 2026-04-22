package graph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getAssetUID(ctx context.Context, db *sql.DB, kind, name, namespace string) (string, error) {
	var uid string
	err := db.QueryRowContext(ctx, `
		SELECT uid FROM assets 
		WHERE kind = $1 AND name = $2 AND namespace = $3
	`, kind, name, namespace).Scan(&uid)
	if err != nil {
		return "", fmt.Errorf("get asset uid: %w", err)
	}
	return uid, nil
}

func findPodsForService(ctx context.Context, cl *kubernetes.Clientset, ns string, selector map[string]string) ([]corev1.Pod, error) {
	pods, err := cl.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: getLabelSelector(selector),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods for service: %w", err)
	}
	return pods.Items, nil
}

func getLabelSelector(selector map[string]string) string {
	var selectors []string
	for key, value := range selector {
		selectors = append(selectors, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(selectors, ",")
}

func BuildEdges(ctx context.Context, cl *kubernetes.Clientset, db *sql.DB, ns string) (int, error) {
	edgeCount := 0

	// 1. USES_SA: for each pod, get pod.Spec.ServiceAccountName, find SA uid in assets table
	pods, err := cl.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if pod.Spec.ServiceAccountName != "" {
			saUID, err := getAssetUID(ctx, db, "ServiceAccount", pod.Spec.ServiceAccountName, pod.Namespace)
			if err != nil {
				continue
			}

			err = InsertEdge(ctx, db, string(pod.UID), saUID, "USES_SA", nil)
			if err != nil {
				continue
			}
			edgeCount++
		}
	}

	// 2. BOUND_TO_ROLE: list ClusterRoleBindings, for each subject where Kind=ServiceAccount, find SA uid in assets
	crbList, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list cluster role bindings: %w", err)
	}

	for _, crb := range crbList.Items {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" {
				saUID, err := getAssetUID(ctx, db, "ServiceAccount", subject.Name, subject.Namespace)
				if err != nil {
					continue
				}

				err = InsertEdge(ctx, db, string(crb.UID), saUID, "BOUND_TO_ROLE", map[string]string{"role": crb.RoleRef.Name})
				if err != nil {
					continue
				}
				edgeCount++
			}
		}
	}

	// 4. MOUNTS_SECRET: for each pod volume with Secret, find secret uid in assets
	for _, pod := range pods.Items {
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil {
				secretUID, err := getAssetUID(ctx, db, "Secret", volume.Secret.SecretName, pod.Namespace)
				if err != nil {
					continue
				}

				err = InsertEdge(ctx, db, string(pod.UID), secretUID, "MOUNTS_SECRET", nil)
				if err != nil {
					continue
				}
				edgeCount++
			}
		}

		// Check container EnvFrom SecretRef
		for _, container := range pod.Spec.Containers {
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					secretUID, err := getAssetUID(ctx, db, "Secret", envFrom.SecretRef.Name, pod.Namespace)
					if err != nil {
						continue
					}

					err = InsertEdge(ctx, db, string(pod.UID), secretUID, "MOUNTS_SECRET", nil)
					if err != nil {
						continue
					}
					edgeCount++
				}
			}
		}
	}

	// 3. EXPOSED_VIA: for each service that exposes pods, find pod uid in assets
	services, err := cl.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list services: %w", err)
	}

	for _, svc := range services.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
			// For simplicity, we'll just check if service has selector
			if svc.Spec.Selector != nil {
				pods, err := cl.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
					LabelSelector: getLabelSelector(svc.Spec.Selector),
				})
				if err != nil {
					continue
				}

				for _, pod := range pods.Items {
					err = InsertEdge(ctx, db, string(pod.UID), string(svc.UID), "EXPOSED_VIA", nil)
					if err != nil {
						continue
					}
					edgeCount++
				}
			}
		}
	}

	return edgeCount, nil
}
