package report

import (
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/paths"
)

func attackPath(score int, secret string) detectors.Finding {
	return detectors.Finding{
		Detector: "attack-path", Severity: "High", Score: score, Title: "Attack Path from the Internet to Secret",
		Description: "app/Deployment/web leads to Secret: app/" + secret + " in 3 steps, risk score 1",
		AttackPath:  []string{"Internet", "Service: app/web", "app/Deployment/web", "Secret: app/" + secret},
		Path: []paths.Step{
			{Kind: "Internet", Name: "Internet"},
			{Kind: "Service", Namespace: "app", Name: "web", Edge: "EXPOSES"},
			{Kind: "Workload", Namespace: "app", Name: "Deployment/web", Edge: "ROUTES_TO"},
			{Kind: "Secret", Namespace: "app", Name: secret, Edge: "MOUNTS_SECRET"},
		},
	}
}

func TestDiagram(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, lang string
		steps      []paths.Step
		text       []string
		want       []string
	}{
		{"names are escaped", "en", attackPath(1, `a<b"c&d`).Path, nil,
			[]string{`a&lt;b&#34;c&amp;d`, "Internet", "mounts", `pn-Secret pn-last`, `pn-Internet pn-first`}},
		{"Russian labels", "ru", attackPath(1, "db").Path, nil, []string{"Интернет", "монтирует", "направляет", ">Deployment<", "app/web"}},
		{"text steps of older findings", "en", nil, []string{"Internet", "Service: web-np", "app/Deployment/web", "SA: app/robot", "Role: cluster-admin"},
			[]string{"pn-Service", "pn-Workload", "pn-ServiceAccount", "pn-Role", ">cluster-admin<"}},
		{"unknown steps get a box", "en", nil, []string{"<script>x</script>"}, []string{"pn-Other", "&lt;script&gt;"}},
		{"long names are cut, the full name is the title", "en", []paths.Step{{Kind: "Secret", Namespace: "ns", Name: strings.Repeat("x", 60)}}, nil,
			[]string{"…</text>", "<title>Secret ns/" + strings.Repeat("x", 60) + "</title>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := string(Diagram(tt.lang, tt.steps, tt.text))
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("diagram lacks %q:\n%s", w, out)
				}
			}
			for _, bad := range []string{"<script", "style=", "<b", "on" + "error", "%!"} {
				if strings.Contains(out, bad) {
					t.Errorf("diagram contains %q:\n%s", bad, out)
				}
			}
		})
	}
	if out := Diagram("en", nil, nil); out != "" {
		t.Errorf("empty path gives %q", out)
	}
}

func TestAttackPathsSection(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ lang, heading, findings string }{{"ru", "Пути атаки", "Находки"}, {"en", "Attack paths", "Findings"}} {
		d := sample()
		d.Lang = tt.lang
		d.Findings = append(d.Findings, attackPath(40, "low"), attackPath(90, "top"))
		out := render(t, d)
		section := strings.Index(out, "<h2>"+tt.heading+"</h2>")
		findings := strings.Index(out, "<h2>"+tt.findings+"</h2>")
		if section < 0 || findings < section {
			t.Fatalf("%s: no attack paths section before the findings", tt.lang)
		}
		top, low := strings.Index(out, "app/top"), strings.Index(out, "app/low")
		if top < 0 || low < top {
			t.Errorf("%s: paths not ordered by score", tt.lang)
		}
		if n := strings.Count(out, `<svg class="pathsvg"`); n != 2 {
			t.Errorf("%s: %d diagrams, want 2", tt.lang, n)
		}
		// Shown in their section, not again among the findings.
		if n := strings.Count(out, "Attack Path from the Internet to Secret") + strings.Count(out, "Путь атаки из интернета до Secret"); n != 2 {
			t.Errorf("%s: attack paths shown %d times, want 2", tt.lang, n)
		}
	}
}
