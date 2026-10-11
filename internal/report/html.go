package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"slices"
	"time"

	"github.com/bigAboo80/shieldops/internal/detectors"
)

//go:embed report.html.tmpl
var reportHTML string

// html/template escapes everything coming from the cluster: names, labels
// and annotations are attacker-controlled.
var tmpl = template.Must(template.New("report").Parse(reportHTML))

// Data is everything a report shows.
type Data struct {
	ScanID    int64
	Generated time.Time
	Assets    int
	Edges     int
	Findings  []detectors.Finding
	detectors.Delta
}

type controlRow struct {
	ID, Description, Class string
	Titles                 []string
	Recommendation         string
}

var fstek17 = []controlRow{
	{ID: "UPD.2", Description: "Access attribute management", Class: "K1/K2/K3"},
	{ID: "UPD.3", Description: "Access control to protected objects", Class: "K1/K2/K3"},
	{ID: "UPD.4", Description: "User access management", Class: "K1/K2/K3"},
	{ID: "UPD.5", Description: "Privileged user management", Class: "K2/K3"},
	{ID: "ZI.1", Description: "User identification and authentication", Class: "K1/K2/K3"},
	{ID: "ZI.2", Description: "Identifier management", Class: "K1/K2/K3"},
	{ID: "ZI.3", Description: "Authentication data management", Class: "K2/K3"},
	{ID: "ZSV.1", Description: "Software component launch control", Class: "K1/K2/K3"},
	{ID: "ZSV.2", Description: "Software installation control", Class: "K2/K3"},
	{ID: "ZTS.1", Description: "Security management function separation", Class: "K1/K2/K3"},
	{ID: "ZTS.3", Description: "Information protection during transfer", Class: "K1/K2/K3"},
	{ID: "ANZ.1", Description: "Vulnerability detection and analysis", Class: "K1/K2/K3"},
	{ID: "ANZ.2", Description: "Update installation control", Class: "K2/K3"},
	{ID: "ANZ.3", Description: "Software operability control", Class: "K2/K3"},
}

// controls fills the FSTEK 17 table: each violated control lists the
// distinct titles of findings mapped to it.
func controls(findings []detectors.Finding) []controlRow {
	rows := slices.Clone(fstek17)
	for i := range rows {
		for _, f := range findings {
			if !slices.ContainsFunc(f.FSTEKControls, func(c detectors.FSTEKControl) bool { return c.ID == rows[i].ID }) {
				continue
			}
			if !slices.Contains(rows[i].Titles, f.Title) {
				rows[i].Titles = append(rows[i].Titles, f.Title)
			}
			if rows[i].Recommendation == "" {
				rows[i].Recommendation = f.Recommendation
			}
		}
	}
	return rows
}

func WriteHTML(w io.Writer, d Data) error {
	err := tmpl.Execute(w, struct {
		Data
		Controls []controlRow
	}{d, controls(d.Findings)})
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	return nil
}
