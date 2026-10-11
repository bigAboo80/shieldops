package report

import (
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
)

func TestWriteHTMLEscapesFindingText(t *testing.T) {
	t.Parallel()
	payload := `<script>alert(1)</script>`
	tests := []struct {
		name    string
		finding detectors.Finding
	}{
		{"title", detectors.Finding{Severity: "High", Title: payload}},
		{"description", detectors.Finding{Severity: "High", Description: payload}},
		{"attack path", detectors.Finding{Severity: "High", AttackPath: []string{payload}}},
		{"remediation", detectors.Finding{Severity: "High", Remediation: payload}},
		{"recommendation", detectors.Finding{Severity: "High", Recommendation: payload,
			FSTEKControls: []detectors.FSTEKControl{{ID: "ANZ.1"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			d := Data{Findings: []detectors.Finding{tt.finding}}
			d.Resolved = []detectors.Finding{tt.finding}
			if err := WriteHTML(&b, d); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(b.String(), payload) {
				t.Errorf("report contains unescaped %q", payload)
			}
		})
	}
}

func TestWriteHTMLDelta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		data     Data
		want     []string
		wantNone []string
	}{
		{"first scan has no delta",
			Data{Findings: []detectors.Finding{{Severity: "High", Title: "T", New: false}}},
			nil, []string{"NEW", "New since last scan", "Resolved since last scan"}},
		{"new and resolved are shown",
			Data{Findings: []detectors.Finding{{Severity: "High", Title: "T", New: true}},
				Delta: detectors.Delta{Baseline: true, New: 1, Resolved: []detectors.Finding{{Title: "Gone"}}}},
			[]string{"NEW", "New since last scan", "Resolved since last scan", "Gone"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			if err := WriteHTML(&b, tt.data); err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.want {
				if !strings.Contains(b.String(), s) {
					t.Errorf("report lacks %q", s)
				}
			}
			for _, s := range tt.wantNone {
				if strings.Contains(b.String(), s) {
					t.Errorf("report contains %q", s)
				}
			}
		})
	}
}
