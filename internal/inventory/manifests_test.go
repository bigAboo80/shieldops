package inventory

import (
	"strings"
	"testing"
)

const testManifests = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: nginx:1.27}]
---
# Source: app/templates/job.yaml
apiVersion: batch/v1
kind: CronJob
metadata: {name: backup, namespace: ops}
spec:
  schedule: "@daily"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup
          containers: [{name: b, image: busybox}]
          restartPolicy: Never
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: backup-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: backup, namespace: ops}]
---
apiVersion: example.com/v1
kind: Widget
metadata: {name: w}
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata: {name: web}
    spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80}]}
`

func TestManifests(t *testing.T) {
	t.Parallel()
	m := NewManifests("apps")
	if err := m.Read(strings.NewReader(testManifests), "k8s/all.yaml"); err != nil {
		t.Fatal(err)
	}
	s := m.Finish(nil)

	t.Run("workloads", func(t *testing.T) {
		t.Parallel()
		got := map[string]string{}
		for _, p := range s.Pods {
			got[Workload(p)] = p.Namespace
		}
		want := map[string]string{"Deployment/web": "apps", "CronJob/backup": "ops"}
		if len(got) != len(want) {
			t.Fatalf("workloads = %v, want %v", got, want)
		}
		for w, ns := range want {
			if got[w] != ns {
				t.Errorf("%s in namespace %q, want %q", w, got[w], ns)
			}
		}
	})
	t.Run("sources", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			key  string
			want Source
		}{
			{SourceKey("Deployment", "apps", "web"), Source{"k8s/all.yaml", 1}},
			{SourceKey("CronJob", "ops", "backup"), Source{"app/templates/job.yaml", 1}},
			{SourceKey("ClusterRoleBinding", "", "backup-admin"), Source{"k8s/all.yaml", 26}},
			{SourceKey("Service", "apps", "web"), Source{"k8s/all.yaml", 36}},
		}
		for _, tt := range tests {
			if got := m.Sources[tt.key]; got != tt.want {
				t.Errorf("Sources[%s] = %v, want %v", tt.key, got, tt.want)
			}
		}
	})
	t.Run("implicit objects", func(t *testing.T) {
		t.Parallel()
		var sas []string
		for _, sa := range s.ServiceAccounts {
			sas = append(sas, sa.Namespace+"/"+sa.Name)
		}
		if strings.Join(sas, ",") != "apps/default" {
			t.Errorf("service accounts = %v, want only apps/default: backup is not defined", sas)
		}
		if len(s.ClusterRoles) != 1 || s.ClusterRoles[0].Name != "cluster-admin" {
			t.Errorf("cluster roles = %v, want built-in cluster-admin", s.ClusterRoles)
		}
		if len(s.Services) != 1 || !Exposed(s.Services[0]) {
			t.Errorf("services = %v, want the LoadBalancer from the List", s.Services)
		}
	})
	t.Run("skipped", func(t *testing.T) {
		t.Parallel()
		if strings.Join(m.Skipped, ",") != "Widget" {
			t.Errorf("skipped = %v, want Widget", m.Skipped)
		}
	})
}

func TestManifestsErrors(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"bad yaml", "kind: [\n", "f.yaml:1"},
		{"bad object", "---\napiVersion: v1\nkind: Pod\nspec: 5\n", "f.yaml:2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewManifests("").Read(strings.NewReader(tt.in), "f.yaml")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %s", err, tt.want)
			}
		})
	}
}
