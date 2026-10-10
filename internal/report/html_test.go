package report

import (
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
)

func TestGenerateHTMLEscapesFindingText(t *testing.T) {
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
			out := GenerateHTML([]detectors.Finding{tt.finding}, 1, 1)
			if strings.Contains(out, payload) {
				t.Errorf("report contains unescaped %q", payload)
			}
		})
	}
}
