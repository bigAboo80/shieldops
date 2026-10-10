package graph

import (
	"maps"
	"slices"
	"testing"

	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func meta(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name)}
}

func secretMeta(ns, name string) metav1.PartialObjectMetadata {
	return metav1.PartialObjectMetadata{ObjectMeta: meta(ns, name)}
}

func nodePort(ns, name string, selector map[string]string) corev1.Service {
	return corev1.Service{ObjectMeta: meta(ns, name), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: selector}}
}

func TestBuildEdges(t *testing.T) {
	t.Parallel()
	web := map[string]string{"app": "web"}

	tests := []struct {
		name string
		snap inventory.Snapshot
		want []Edge
	}{
		{
			name: "pod uses explicit and default service account",
			snap: inventory.Snapshot{
				Pods: []corev1.Pod{
					{ObjectMeta: meta("a", "p1"), Spec: corev1.PodSpec{ServiceAccountName: "robot"}},
					{ObjectMeta: meta("a", "p2")},
				},
				ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: meta("a", "robot")}, {ObjectMeta: meta("a", "default")}},
			},
			want: []Edge{
				{SourceUID: "a/p1", TargetUID: "a/robot", EdgeType: EdgeUsesSA},
				{SourceUID: "a/p2", TargetUID: "a/default", EdgeType: EdgeUsesSA},
			},
		},
		{
			name: "cluster role binding points from service account to binding",
			snap: inventory.Snapshot{
				ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: meta("a", "robot")}},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
					ObjectMeta: meta("", "robot-admin"),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Namespace: "a", Name: "robot"},
						{Kind: rbacv1.GroupKind, Name: "system:masters"},
						{Kind: rbacv1.ServiceAccountKind, Namespace: "gone", Name: "ghost"},
					},
				}},
			},
			want: []Edge{
				{SourceUID: "a/robot", TargetUID: "/robot-admin", EdgeType: EdgeBoundToRole, Properties: map[string]string{"role": "cluster-admin"}},
			},
		},
		{
			name: "secrets from volume, projected, envFrom and env are deduplicated",
			snap: inventory.Snapshot{
				Pods: []corev1.Pod{{
					ObjectMeta: meta("a", "p"),
					Spec: corev1.PodSpec{
						Volumes: []corev1.Volume{
							{Name: "v1", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "s1"}}},
							{Name: "v2", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
								{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "s2"}}},
							}}}},
						},
						InitContainers: []corev1.Container{{EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "s3"}}}}}},
						Containers: []corev1.Container{{Env: []corev1.EnvVar{
							{Name: "A", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "s1"}, Key: "k"}}},
							{Name: "B", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "missing"}, Key: "k"}}},
						}}},
					},
				}},
				Secrets: []metav1.PartialObjectMetadata{secretMeta("a", "s1"), secretMeta("a", "s2"), secretMeta("a", "s3")},
			},
			want: []Edge{
				{SourceUID: "a/p", TargetUID: "a/s1", EdgeType: EdgeMountsSecret},
				{SourceUID: "a/p", TargetUID: "a/s2", EdgeType: EdgeMountsSecret},
				{SourceUID: "a/p", TargetUID: "a/s3", EdgeType: EdgeMountsSecret},
			},
		},
		{
			name: "service exposes only matching pods in its own namespace",
			snap: inventory.Snapshot{
				Pods: []corev1.Pod{
					{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web", UID: "a/web", Labels: web}},
					{ObjectMeta: metav1.ObjectMeta{Namespace: "b", Name: "web", UID: "b/web", Labels: web}},
					{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "db", UID: "a/db", Labels: map[string]string{"app": "db"}}},
				},
				Services: []corev1.Service{
					nodePort("a", "web-np", web),
					nodePort("a", "no-selector", nil),
					{ObjectMeta: meta("a", "internal"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: web}},
				},
			},
			want: []Edge{
				{SourceUID: "a/web", TargetUID: "a/web-np", EdgeType: EdgeExposedVia},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildEdges(&tt.snap)
			if !slices.EqualFunc(got, tt.want, edgeEqual) {
				t.Errorf("BuildEdges() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func edgeEqual(a, b Edge) bool {
	return a.SourceUID == b.SourceUID && a.TargetUID == b.TargetUID && a.EdgeType == b.EdgeType && maps.Equal(a.Properties, b.Properties)
}
