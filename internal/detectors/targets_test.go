package detectors_test

import (
	"fmt"
	"slices"
	"testing"
)

// TestTargets checks the objects a fix of each finding changes.
func TestTargets(t *testing.T) {
	t.Parallel()
	got := map[string][]string{}
	for _, f := range findingsOf(t) {
		if len(f.Targets) == 0 || f.Targets[0].Kind == "" || f.Targets[0].Name == "" {
			t.Errorf("%s %q: no target", f.Detector, f.Description)
		}
		var ts []string
		for _, tg := range f.Targets {
			ts = append(ts, fmt.Sprintf("%s %s/%s %s %s", tg.Kind, tg.Namespace, tg.Name, tg.Container, tg.Value))
		}
		got[f.Detector] = append(got[f.Detector], fmt.Sprint(ts))
	}
	want := map[string][]string{
		"cluster-admin-sa": {
			"[Pod app/admin-pod   ServiceAccount app/admin-sa   ClusterRoleBinding /admin-binding  ]",
			"[Deployment p3/rbac-safe   ServiceAccount p3/narrow   ClusterRoleBinding /admin-crb  ]",
		},
		"exposed-secret":       {"[Deployment app/web   Secret app/db-creds  ]"},
		"exposed-cve":          {"[Deployment app/web  ]"},
		"privileged-container": {"[Deployment p3/priv-exposed c ]", "[Deployment p3/sysadmin init ]"},
		"host-namespaces":      {"[Deployment p3/host  hostNetwork Deployment p3/host  hostPID]"},
		"host-path": {
			"[Deployment p3/paths  /data/logs]", "[Deployment p3/paths  /etc/kubernetes/pki]", "[Deployment p3/paths  /var/run/docker.sock]",
		},
		"latest-tag": {"[Deployment p3/floating  nginx Deployment p3/floating  reg.local:5000/app:latest]"},
		"wildcard-rbac": {
			"[Deployment p3/rbac-exposed   ServiceAccount p3/wild   ClusterRole /wild-cr  ]",
			"[Deployment p3/rbac-internal   ServiceAccount p3/ns-wild   Role p3/wild-role  ]",
		},
	}
	for detector, w := range want {
		g := got[detector]
		slices.Sort(g)
		slices.Sort(w)
		if !slices.Equal(g, w) {
			t.Errorf("%s targets:\n got %q\nwant %q", detector, g, w)
		}
	}
	for _, ns := range got["no-network-policy"] {
		if ns != "[Namespace /app  ]" && ns != "[Namespace /p3  ]" {
			t.Errorf("no-network-policy target %s", ns)
		}
	}
}
