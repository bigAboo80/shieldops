package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const fixtures = "../../test/e2e/fixtures.yaml"

// runCheck runs check with output to a file and returns the output.
func runCheck(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	err := runCheckCmd(context.Background(), append([]string{"-output", out}, args...))
	b, rerr := os.ReadFile(out)
	if rerr != nil && err == nil {
		t.Fatal(rerr)
	}
	return string(b), err
}

func TestCheckFixtures(t *testing.T) {
	t.Parallel()
	out, err := runCheck(t, "-format", "json", fixtures)
	if !errors.Is(err, errGate) {
		t.Fatalf("err = %v, want the gate to fail on the fixtures", err)
	}
	var found []checked
	if err := json.Unmarshal([]byte(out), &found); err != nil {
		t.Fatal(err)
	}
	// The fixtures expect one finding per detector in the cluster; without
	// images there is no exposed-cve, and attack-path joins them.
	var got []string
	for _, f := range found {
		got = append(got, f.Detector)
		if f.Source.File == "" {
			t.Errorf("%s %s: no source", f.Detector, f.Description)
		}
	}
	slices.Sort(got)
	want := []string{"attack-path", "cluster-admin-sa", "exposed-secret", "host-namespaces", "host-path",
		"latest-tag", "no-network-policy", "privileged-container", "wildcard-rbac"}
	if !slices.Equal(got, want) {
		t.Errorf("detectors = %v, want %v", got, want)
	}
}

func TestCheckGate(t *testing.T) {
	t.Parallel()
	baseline := filepath.Join(t.TempDir(), "baseline")
	if _, err := runCheck(t, "-fail-on", "none", "-write-baseline", baseline, fixtures); err != nil {
		t.Fatalf("-fail-on none: %v", err)
	}
	tests := []struct {
		name string
		args []string
		gate bool
	}{
		{"default high", nil, true},
		{"critical", []string{"-fail-on", "critical"}, true},
		{"baseline accepts all", []string{"-baseline", baseline}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := runCheck(t, append(tt.args, fixtures)...)
			if errors.Is(err, errGate) != tt.gate {
				t.Errorf("err = %v, want gate %v", err, tt.gate)
			}
		})
	}
}

func TestCheckClean(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	clean := `apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      automountServiceAccountToken: false
      containers: [{name: api, image: "registry.example/api:1.4.2"}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: shop}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
`
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCheck(t, "-fail-on", "low", dir)
	if err != nil {
		t.Fatalf("err = %v, output:\n%s", err, out)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("output = %q, want no findings", out)
	}
}

func TestCheckInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{"no files", nil},
		{"missing file", []string{"missing.yaml"}},
		{"bad threshold", []string{"-fail-on", "severe", fixtures}},
		{"bad format", []string{"-format", "xml", fixtures}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := runCheck(t, tt.args...)
			if exitCode(err) != 2 {
				t.Errorf("err = %v: exit code %d, want 2", err, exitCode(err))
			}
		})
	}
}

func TestCheckFormats(t *testing.T) {
	t.Parallel()
	t.Run("sarif", func(t *testing.T) {
		t.Parallel()
		out, _ := runCheck(t, "-format", "sarif", fixtures)
		var s sarif
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			t.Fatal(err)
		}
		if s.Version != "2.1.0" || len(s.Runs) != 1 || len(s.Runs[0].Results) != 9 {
			t.Fatalf("sarif = version %q, %d runs", s.Version, len(s.Runs))
		}
		rules := map[string]bool{}
		for _, r := range s.Runs[0].Tool.Driver.Rules {
			rules[r.ID] = true
		}
		for _, r := range s.Runs[0].Results {
			if !rules[r.RuleID] || r.PartialFingerprints["shieldops/v1"] == "" || len(r.Locations) != 1 {
				t.Errorf("result %+v: want a known rule, a fingerprint and a location", r)
			}
		}
	})
	t.Run("gitlab", func(t *testing.T) {
		t.Parallel()
		out, _ := runCheck(t, "-format", "gitlab", fixtures)
		var issues []codeQualityIssue
		if err := json.Unmarshal([]byte(out), &issues); err != nil {
			t.Fatal(err)
		}
		if len(issues) != 9 {
			t.Fatalf("%d issues, want 9", len(issues))
		}
		for _, i := range issues {
			if i.Fingerprint == "" || i.Location.Path == "" || i.Location.Lines.Begin < 1 ||
				!slices.Contains([]string{"info", "minor", "major", "critical"}, i.Severity) {
				t.Errorf("issue %+v is not a valid Code Quality issue", i)
			}
		}
	})
}
