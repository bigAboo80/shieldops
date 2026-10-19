package trivy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseResult(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    []vuln
		wantErr bool
	}{
		{"no results", `{"Results":[]}`, nil, false},
		{
			"same CVE in two layers is reported once",
			`{"Results":[
				{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"openssl","Title":"t1"}]},
				{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"libssl","Title":"t1"},
				                    {"VulnerabilityID":"CVE-2","Severity":"CRITICAL","PkgName":"zlib","Title":"t2"}]}
			]}`,
			[]vuln{{"CVE-1", "HIGH", "openssl", "", "", "t1"}, {"CVE-2", "CRITICAL", "zlib", "", "", "t2"}},
			false,
		},
		{
			"fixed version",
			`{"Results":[{"Vulnerabilities":[
				{"VulnerabilityID":"CVE-3","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"3.0.13","FixedVersion":"3.0.15","Title":"t3"},
				{"VulnerabilityID":"CVE-4","Severity":"HIGH","PkgName":"libx","InstalledVersion":"1.2","FixedVersion":"","Title":"t4"}]}]}`,
			[]vuln{{"CVE-3", "CRITICAL", "openssl", "3.0.13", "3.0.15", "t3"}, {"CVE-4", "HIGH", "libx", "1.2", "", "t4"}},
			false,
		},
		{"garbage", `not json`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseResult([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseResult() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("parseResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBrief(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 300)
	tests := []struct {
		err  string
		want string
	}{
		{"trivy: exit status 1: FATAL unable to find the specified image \"r/x\" in [docker containerd]: 4 errors\n* docker error", "no access to the image in its registry (a private registry needs credentials for trivy)"},
		{"trivy: exit status 1: GET https://r/v2/: DENIED: access forbidden", "no access to the image in its registry (a private registry needs credentials for trivy)"},
		{"trivy: exit status 1: timeout\nmore", "trivy: exit status 1: timeout"},
		{long, long[:200] + "…"},
	}
	for _, tt := range tests {
		if got := brief(errors.New(tt.err)); got != tt.want {
			t.Errorf("brief(%q) = %q, want %q", tt.err, got, tt.want)
		}
	}
}
