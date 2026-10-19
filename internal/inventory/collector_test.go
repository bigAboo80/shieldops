package inventory

import (
	"context"
	"errors"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
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
		&rbacv1.RoleBinding{ObjectMeta: om("a", "rb-a")},
		&rbacv1.RoleBinding{ObjectMeta: om("b", "rb-b")},
		&rbacv1.Role{ObjectMeta: om("a", "role-a")},
		&rbacv1.ClusterRole{ObjectMeta: om("", "cr")},
		&networkingv1.NetworkPolicy{ObjectMeta: om("a", "np-a")},
		&networkingv1.NetworkPolicy{ObjectMeta: om("b", "np-b")},
		// Never listed: the scanner has no RBAC for Secrets.
		&corev1.Secret{ObjectMeta: om("b", "unreferenced")},
	)

	tests := []struct {
		name    string
		ns      string
		exclude []string
		want    []string
	}{
		{"all namespaces", "", nil, []string{"ClusterRoleBinding/crb", "NetworkPolicy/np-a", "NetworkPolicy/np-b", "Pod/pod-a", "Pod/pod-a2", "Pod/pod-b", "RoleBinding/rb-a", "RoleBinding/rb-b", "Secret/sec-a", "Service/svc-a", "ServiceAccount/sa-a"}},
		{"single namespace keeps cluster scoped bindings", "a", nil, []string{"ClusterRoleBinding/crb", "NetworkPolicy/np-a", "Pod/pod-a", "Pod/pod-a2", "RoleBinding/rb-a", "Secret/sec-a", "Service/svc-a", "ServiceAccount/sa-a"}},
		{"excluded namespace is dropped with its secrets", "", []string{"a"}, []string{"ClusterRoleBinding/crb", "NetworkPolicy/np-b", "Pod/pod-b", "RoleBinding/rb-b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap, err := Collect(context.Background(), kube, tt.ns, tt.exclude)
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
			if tt.ns == "" && tt.exclude == nil && (len(snap.Roles) != 1 || len(snap.ClusterRoles) != 1) {
				t.Errorf("roles = %d, cluster roles = %d; want 1 and 1", len(snap.Roles), len(snap.ClusterRoles))
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

func TestCollectErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	notFound := apierrors.NewNotFound(networkingv1.Resource("networkpolicies"), "")
	tests := []struct {
		resource string
		err      error
		wantErr  bool
	}{
		// An API group missing on the server is skipped, anything else fails the scan.
		{"networkpolicies", notFound, false},
		{"rolebindings", notFound, false},
		{"roles", notFound, false},
		{"clusterroles", notFound, false},
		{"networkpolicies", boom, true},
		{"rolebindings", boom, true},
		{"roles", boom, true},
		{"clusterroles", boom, true},
		{"pods", boom, true},
		{"pods", notFound, true}, // core resources always exist
	}
	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			t.Parallel()
			kube := kubefake.NewSimpleClientset()
			kube.PrependReactor("list", tt.resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, tt.err
			})
			_, err := Collect(context.Background(), kube, "", nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, tt.err) {
				t.Errorf("Collect() error = %v, want it to wrap %v", err, tt.err)
			}
		})
	}
}

func TestPodFacts(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		name string
		spec corev1.PodSpec
		want []Fact
	}{
		{"nothing", corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1"}}}, nil},
		{"host flags", corev1.PodSpec{HostNetwork: true, HostPID: true, HostIPC: true},
			[]Fact{{FactHostIPC, "true"}, {FactHostNetwork, "true"}, {FactHostPID, "true"}}},
		{"host paths, other volumes ignored", corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "a", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
			{Name: "b", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		}}, []Fact{{FactHostPath, "/etc"}}},
		{"privileged init container", corev1.PodSpec{InitContainers: []corev1.Container{
			{Name: "init", Image: "app:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}},
			[]Fact{{FactPrivileged, "init"}}},
		{"SYS_ADMIN needs allowPrivilegeEscalation", corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", Image: "app:1", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &yes, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}}},
			{Name: "b", Image: "app:1", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}}},
			{Name: "c", Image: "app:1", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &yes}},
		}}, []Fact{{FactPrivileged, "a"}}},
		{"unpinned images", corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", Image: "nginx"}, {Name: "b", Image: "nginx:latest"}, {Name: "c", Image: "reg:5000/app"},
			{Name: "d", Image: "reg:5000/app:2"}, {Name: "e", Image: "nginx:latest@sha256:abc"}, {Name: "f", Image: "app@sha256:abc"},
		}}, []Fact{{FactLatestImage, "nginx"}, {FactLatestImage, "nginx:latest"}, {FactLatestImage, "reg:5000/app"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := PodFacts(corev1.Pod{Spec: tt.spec}); !slices.Equal(got, tt.want) {
				t.Errorf("PodFacts() = %v, want %v", got, tt.want)
			}
		})
	}
}
