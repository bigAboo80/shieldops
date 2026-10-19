package inventory

import "testing"

func TestSensitiveHostPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"/etc", true},
		{"/etc/kubernetes/", true},
		{"/var/run/docker.sock", true},
		{"/run/containerd/containerd.sock", true},
		{"/run/k3s/containerd/containerd.sock", true},
		{"/var/lib/rancher/k3s/server", true},
		{"/run/crio/crio.sock", true},
		{"/var/snap/microk8s/common/run/containerd.sock", true},
		{"/var/lib/kubelet/pods", true},
		{"/run/flannel", false},
		{"/opt/cni/bin", false},
		{"/etcd-data", false},
		{"/run/k3s-other", false},
	}
	for _, tt := range tests {
		if got := SensitiveHostPath(tt.path); got != tt.want {
			t.Errorf("SensitiveHostPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
