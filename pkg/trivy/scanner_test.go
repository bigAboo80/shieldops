package trivy

import (
	"slices"
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
			[]vuln{{"CVE-1", "HIGH", "openssl", "t1"}, {"CVE-2", "CRITICAL", "zlib", "t2"}},
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
