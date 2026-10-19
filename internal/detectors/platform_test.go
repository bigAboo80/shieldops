package detectors_test

import (
	"context"
	"slices"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/inventory"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPlatformNamespaces(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, flag, own string
		in, out         []string
	}{
		{"defaults", "", "", []string{"kube-system", "kube-flannel", "monitoring", "yandex-system"}, []string{"prod", "shieldops"}},
		{"own namespace", "", "shieldops", []string{"kube-system", "shieldops"}, []string{"prod"}},
		{"added", "legacy, infra", "", []string{"kube-system", "legacy", "infra"}, []string{"prod"}},
		{"defaults off", "-", "shieldops", []string{"shieldops"}, []string{"kube-system", "monitoring"}},
		{"defaults off, added", "-,infra", "", []string{"infra"}, []string{"kube-system"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := detectors.PlatformNamespaces(tt.flag, tt.own)
			for _, ns := range tt.in {
				if !slices.Contains(got, ns) {
					t.Errorf("%q not platform in %v", ns, got)
				}
			}
			for _, ns := range tt.out {
				if slices.Contains(got, ns) {
					t.Errorf("%q is platform in %v", ns, got)
				}
			}
			if slices.Contains(got, "-") || slices.Contains(got, "") {
				t.Errorf("flag syntax leaked into %v", got)
			}
		})
	}
}

// platformSnapshot: privileged pods of applications and of the platform,
// a static pod outside the platform namespaces, an exposed privileged pod in
// kube-system.
func platformSnapshot() *inventory.Snapshot {
	yes := true
	priv := corev1.PodSpec{Containers: []corev1.Container{container("c", "app:1.0@sha256:0123456789abcdef", &corev1.SecurityContext{Privileged: &yes})}}
	static := func(ns, name string) corev1.Pod {
		ctrl := true
		meta := om(ns, name, nil)
		meta.OwnerReferences = []metav1.OwnerReference{{Kind: "Node", Name: "node1", Controller: &ctrl}}
		return corev1.Pod{ObjectMeta: meta, Spec: priv}
	}
	pods := slices.Concat(
		deployment("prod", "web", 1, priv),
		deployment("shieldops", "shieldops", 1, priv),
		deployment("kube-system", "proxy", 1, priv),
		[]corev1.Pod{static("kube-system", "etcd-node1"), static("infra", "haproxy-node1")},
		[]corev1.Pod{{ObjectMeta: om("prod", "bare", nil), Spec: priv}},
	)
	pods[2].Labels["app"] = "proxy"
	pods[2].Spec.NodeName = "node1"
	pods[2].Spec.Volumes = []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "proxy-tls"}}}}
	return &inventory.Snapshot{
		Pods: pods,
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: om("prod", "default", nil)}, {ObjectMeta: om("kube-system", "default", nil)},
			{ObjectMeta: om("shieldops", "default", nil)}, {ObjectMeta: om("infra", "default", nil)}},
		Services: []corev1.Service{lbService("kube-system", "proxy")},
	}
}

func TestMarkPlatform(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	id := loadScan(t, ctx, db, platformSnapshot())
	var all []detectors.Finding
	for _, d := range detectors.All {
		f, err := d.Detect(ctx, db, id)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, f...)
	}
	if err := detectors.MarkPlatform(ctx, db, id, all, detectors.PlatformNamespaces("", "shieldops")); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"prod/Deployment/web":            false,
		"prod/Pod/bare":                  false, // a bare pod of the team, not a static pod
		"shieldops/Deployment/shieldops": true,
		"kube-system/Deployment/proxy":   true,
		"kube-system/Pod/etcd-node1":     true,
		"infra/Pod/haproxy-node1":        true, // static pod outside the platform namespaces
	}
	got := map[string]bool{}
	var platformPath bool
	for _, f := range all {
		if f.Detector == "privileged-container" {
			got[f.Targets[0].Namespace+"/"+f.Targets[0].Kind+"/"+f.Targets[0].Name] = f.Platform
		}
		// The path from the Internet through the platform pod stays a finding.
		if f.Detector == "attack-path" && f.Namespace == "kube-system" {
			platformPath = platformPath || f.Platform
		}
	}
	for w, p := range want {
		if g, ok := got[w]; !ok || g != p {
			t.Errorf("%s: platform = %v (found %v), want %v", w, g, ok, p)
		}
	}
	if !platformPath {
		t.Error("no attack path through the exposed platform pod, or it is not marked platform")
	}
}
