package inventory

import (
	"context"
	"slices"
	"testing"

	"github.com/bigAboo80/shieldops/internal/connector"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
)

func TestCollect(t *testing.T) {
	t.Parallel()
	om := func(ns, name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)}
	}
	secret := func(ns, name string) *metav1.PartialObjectMetadata {
		return &metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: om(ns, name),
		}
	}
	kube := kubefake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: om("a", "pod-a"), Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "nginx:1"}}}},
		&corev1.Pod{ObjectMeta: om("b", "pod-b")},
		&corev1.ServiceAccount{ObjectMeta: om("a", "sa-a")},
		&corev1.Service{ObjectMeta: om("a", "svc-a")},
		&rbacv1.ClusterRoleBinding{ObjectMeta: om("", "crb")},
	)
	scheme := metafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	md := metafake.NewSimpleMetadataClient(scheme, []runtime.Object{secret("a", "sec-a"), secret("b", "sec-b")}...)
	cl := &connector.Clients{Kube: kube, Metadata: md}

	tests := []struct {
		name string
		ns   string
		want []string
	}{
		{"all namespaces", "", []string{"ClusterRoleBinding/crb", "Pod/pod-a", "Pod/pod-b", "Secret/sec-a", "Secret/sec-b", "Service/svc-a", "ServiceAccount/sa-a"}},
		{"single namespace keeps cluster scoped bindings", "a", []string{"ClusterRoleBinding/crb", "Pod/pod-a", "Secret/sec-a", "Service/svc-a", "ServiceAccount/sa-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap, err := Collect(context.Background(), cl, tt.ns)
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
