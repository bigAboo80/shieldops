package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/shieldops/core/internal/detectors"
)

func buildComplianceTable(findings []detectors.Finding) string {
	type controlMeta struct{ desc, class string }
	allControls := []struct{ id, desc, class string }{
		{"UPD.2", "Access attribute management", "K1/K2/K3"},
		{"UPD.3", "Access control to protected objects", "K1/K2/K3"},
		{"UPD.4", "User access management", "K1/K2/K3"},
		{"UPD.5", "Privileged user management", "K2/K3"},
		{"ZI.1", "User identification and authentication", "K1/K2/K3"},
		{"ZI.2", "Identifier management", "K1/K2/K3"},
		{"ZI.3", "Authentication data management", "K2/K3"},
		{"ZSV.1", "Software component launch control", "K1/K2/K3"},
		{"ZSV.2", "Software installation control", "K2/K3"},
		{"ZTS.1", "Security management function separation", "K1/K2/K3"},
		{"ZTS.3", "Information protection during transfer", "K1/K2/K3"},
		{"ANZ.1", "Vulnerability detection and analysis", "K1/K2/K3"},
		{"ANZ.2", "Update installation control", "K2/K3"},
		{"ANZ.3", "Software operability control", "K2/K3"},
	}
	violated := map[string][]detectors.Finding{}
	for _, f := range findings {
		for _, c := range f.FSTEKControls {
			// deduplicate by Title
			alreadyAdded := false
			for _, existing := range violated[c.ID] {
				if existing.Title == f.Title { alreadyAdded = true; break }
			}
			if !alreadyAdded {
				violated[c.ID] = append(violated[c.ID], f)
			}
		}
	}
	var b strings.Builder
	b.WriteString(`<h2 style="color:#00B4D8;margin-top:40px">FSTEK Order No.17 Compliance</h2>`)
	b.WriteString(`<table class="ctable"><thead><tr><th>ID</th><th>Description</th><th>Class</th><th>Status</th><th>Findings</th><th>Recommendation</th></tr></thead><tbody>`)
	for _, c := range allControls {
		ff := violated[c.id]
		status := `<span style="color:#22c55e;font-weight:600">&#10003; OK</span>`
		findCell, recCell := "&#8212;", "&#8212;"
		if len(ff) > 0 {
			status = `<span style="color:#f59e0b;font-weight:600">&#9888; FAIL</span>`
			var titles []string
			for _, f := range ff { titles = append(titles, f.Title) }
			findCell = strings.Join(titles, "<br>")
			recCell = ff[0].Recommendation
		}
		b.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, c.id, c.desc, c.class, status, findCell, recCell))
	}
	b.WriteString("</tbody></table>")
	_ = controlMeta{}
	return b.String()
}

func GenerateHTML(findings []detectors.Finding, assetCount int, edgeCount int) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><title>ShieldOps Security Report</title><style>
body{background:#0D1B2A;color:#fff;font-family:'Segoe UI',sans-serif;margin:0;padding:20px}
h1{color:#00B4D8}.header{text-align:center;border-bottom:2px solid #00B4D8;padding-bottom:20px;margin-bottom:30px}
.summary{background:#1b263b;border-radius:10px;padding:20px;margin-bottom:30px;display:flex;justify-content:space-around}
.stat{text-align:center}.stat-num{font-size:2em;color:#00B4D8;font-weight:bold}
.card{background:#1b263b;border-radius:10px;padding:20px;margin-bottom:20px}
.critical{border-left:5px solid #ff4d4d}.high{border-left:5px solid #ff9933}
.badge{display:inline-block;padding:5px 12px;border-radius:5px;font-weight:bold;font-size:0.85em}
.badge-critical{background:#ff4d4d}.badge-high{background:#ff9933}
.path{display:flex;align-items:center;flex-wrap:wrap;margin:15px 0}
.step{padding:8px 12px;background:#3a4a6c;border-radius:5px;margin:4px}
.arrow{color:#00B4D8;margin:0 5px;font-size:1.2em}
.fix{background:#1a3a1a;border-left:5px solid #06D6A0;padding:15px;border-radius:5px;margin-top:15px}
.footer{text-align:center;margin-top:30px;border-top:2px solid #00B4D8;padding-top:20px;color:#888}
.ctable{width:100%;border-collapse:collapse;margin-top:24px;font-size:13px}.ctable th{background:#1e293b;color:#94a3b8;padding:10px 12px;text-align:left;border-bottom:2px solid #334155}.ctable td{padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:top}.ctable tr:hover td{background:#0f172a}
</style></head><body><div class="header"><h1>ShieldOps Security Report</h1><p>`)
	b.WriteString(time.Now().Format("2006-01-02 15:04:05"))
	b.WriteString(`</p></div><div class="summary">`)
	b.WriteString(fmt.Sprintf(`<div class="stat"><div class="stat-num">%d</div><div>Assets</div></div>`, assetCount))
	b.WriteString(fmt.Sprintf(`<div class="stat"><div class="stat-num">%d</div><div>Edges</div></div>`, edgeCount))
	b.WriteString(fmt.Sprintf(`<div class="stat"><div class="stat-num">%d</div><div>Findings</div></div>`, len(findings)))
	b.WriteString(`</div>`)
	if len(findings) == 0 {
		b.WriteString(`<div class="card"><h3 style="color:#06D6A0">No critical findings detected</h3></div>`)
	}
	for _, f := range findings {
		sev, badge := "high", "badge-high"
		if f.Severity == "Critical" { sev, badge = "critical", "badge-critical" }
		b.WriteString(fmt.Sprintf(`<div class="card %s"><span class="badge %s">%s</span><h3>%s</h3><p>%s</p><div class="path">`, sev, badge, f.Severity, f.Title, f.Description))
		for i, step := range f.AttackPath {
			if i > 0 { b.WriteString(`<span class="arrow">→</span>`) }
			b.WriteString(fmt.Sprintf(`<span class="step">%s</span>`, step))
		}
		b.WriteString(`</div><div class="fix"><strong>Remediation:</strong> `)
		b.WriteString(f.Remediation)
		b.WriteString(`</div></div>`)
	}
	b.WriteString(buildComplianceTable(findings))
	b.WriteString(`<div class="footer">ShieldOps v0.1 · shieldops.tech</div></body></html>`)
	return b.String()
}
