package inventory

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestCollect(t *testing.T) {
	t.Parallel()
	om := func(ns, name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)}
	}
	secretVol := corev1.Volume{Name: "v", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "sec-a"}}}
	kube := kubefake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: om("a", "pod-a"), Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "nginx:1"}}, Volumes: []corev1.Volume{secretVol}}},
		&corev1.Pod{ObjectMeta: om("a", "pod-a2"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVol}}},
		&corev1.Pod{ObjectMeta: om("b", "pod-b")},
		&corev1.ServiceAccount{ObjectMeta: om("a", "sa-a")},
		&corev1.Service{ObjectMeta: om("a", "svc-a")},
		&rbacv1.ClusterRoleBinding{ObjectMeta: om("", "crb")},
		// Never listed: the scanner has no RBAC for Secrets.
		&corev1.Secret{ObjectMeta: om("b", "unreferenced")},
	)

	tests := []struct {
		name string
		ns   string
		want []string
	}{
		{"all namespaces", "", []string{"ClusterRoleBinding/crb", "Pod/pod-a", "Pod/pod-a2", "Pod/pod-b", "Secret/sec-a", "Service/svc-a", "ServiceAccount/sa-a"}},
		{"single namespace keeps cluster scoped bindings", "a", []string{"ClusterRoleBinding/crb", "Pod/pod-a", "Pod/pod-a2", "Secret/sec-a", "Service/svc-a", "ServiceAccount/sa-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap, err := Collect(context.Background(), kube, tt.ns)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			var got []string
			for _, a := range snap.Assets() {
				got = append(got, a.Kind+"/"+a.Name)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("assets = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorkload(t *testing.T) {
	t.Parallel()
	ctrl := true
	owned := func(kind, name string, lbl map[string]string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p-123", Labels: lbl,
			OwnerReferences: []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &ctrl}}}}
	}
	tests := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{"bare pod", corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}, "Pod/p"},
		{"deployment via replicaset", owned("ReplicaSet", "web-5d9c7b", map[string]string{"pod-template-hash": "5d9c7b"}), "Deployment/web"},
		{"bare replicaset", owned("ReplicaSet", "rs", nil), "ReplicaSet/rs"},
		{"statefulset", owned("StatefulSet", "db", nil), "StatefulSet/db"},
		{"static pod owned by node", owned("Node", "cp1", nil), "Pod/p-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Workload(tt.pod); got != tt.want {
				t.Errorf("Workload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPodImages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec corev1.PodSpec
		want []string
	}{
		{"no containers", corev1.PodSpec{}, nil},
		{
			"init and sidecar images, deduplicated",
			corev1.PodSpec{
				InitContainers: []corev1.Container{{Image: "busybox:1.36"}},
				Containers:     []corev1.Container{{Image: "app:2"}, {Image: "envoy:1"}, {Image: "busybox:1.36"}},
			},
			[]string{"busybox:1.36", "app:2", "envoy:1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := PodImages(corev1.Pod{Spec: tt.spec}); !slices.Equal(got, tt.want) {
				t.Errorf("PodImages() = %v, want %v", got, tt.want)
			}
		})
	}
}
