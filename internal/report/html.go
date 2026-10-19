package report

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"slices"
	"time"

	"github.com/bigAboo80/shieldops/internal/detectors"
)

//go:embed report.html.tmpl
var reportHTML string

// Data is everything a report shows.
type Data struct {
	ScanID    int64
	Generated time.Time
	Assets    int
	Edges     int
	Findings  []detectors.Finding
	detectors.Delta

	Cluster  string         // name of the cluster for the cover and the footer; empty: not shown
	SignKey  string         // fingerprint of the key the report is signed with; empty: unsigned
	Version  string         // ShieldOps version for the footer
	Lang     string         // "ru" (default) or "en"
	Location *time.Location // times are shown in it; nil: Europe/Moscow
	FSTEK    string         // order the measures table follows, "117" or "17"; empty: no table
}

// Langs are the languages of the report.
var Langs = []string{"ru", "en"}

// moscow is the default zone. Moscow has had no daylight saving time since
// 2014, so a fixed +03:00 is exact when the zone database is missing.
var moscow = func() *time.Location {
	if loc, err := time.LoadLocation("Europe/Moscow"); err == nil {
		return loc
	}
	return time.FixedZone("MSK", 3*60*60)
}()

// pages holds the report template per language. html/template escapes
// everything coming from the cluster: names, labels and annotations are
// attacker-controlled.
var pages = func() map[string]*template.Template {
	m := map[string]*template.Template{}
	for _, l := range Langs {
		funcs := template.FuncMap{
			"t":        func(key string, args ...any) string { return t(l, key, args...) },
			"sevLabel": func(s string) string { return sevLabel(l, s) },
			"diagram":  func(f detectors.Finding) template.HTML { return Diagram(l, f.Path, f.AttackPath) },
		}
		m[l] = template.Must(template.New("report").Funcs(funcs).Parse(reportHTML))
	}
	return m
}()

type controlRow struct {
	ID, Name, Classes string
	Titles            []string
	Recommendation    string
}

// controls fills the table of measures of a FSTEK order: every measure of
// the order, and for a violated one the distinct titles of findings mapped
// to it.
func controls(lang, order string, findings []detectors.Finding) []controlRow {
	var rows []controlRow
	for _, c := range detectors.ControlsOf(order) {
		row := controlRow{ID: c.ID, Name: c.NameRU, Classes: c.Classes}
		if lang == "en" {
			row.Name = c.NameEN
		}
		for _, f := range findings {
			if !slices.Contains(f.ControlIDs(order), c.ID) {
				continue
			}
			if !slices.Contains(row.Titles, f.Title) {
				row.Titles = append(row.Titles, f.Title)
			}
			if row.Recommendation == "" {
				row.Recommendation = f.Recommendation
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// severities in report order; findings of other severities come last.
var severities = []string{"Critical", "High", "Medium", "Low"}

type group struct {
	Severity string
	Findings []detectors.Finding
}

// groups orders findings by severity, keeping detector order within one.
func groups(findings []detectors.Finding) []group {
	var out []group
	add := func(sev string, match func(string) bool) {
		g := group{Severity: sev}
		for _, f := range findings {
			if match(f.Severity) {
				g.Findings = append(g.Findings, f)
			}
		}
		if len(g.Findings) > 0 {
			out = append(out, g)
		}
	}
	for _, sev := range severities {
		add(sev, func(s string) bool { return s == sev })
	}
	add("", func(s string) bool { return !slices.Contains(severities, s) })
	return out
}

type sevCount struct {
	Severity string
	Count    int
}

// verdict is the one-line conclusion for management.
func verdict(l string, counts map[string]int, total int) string {
	switch {
	case counts["Critical"] > 0:
		return t(l, "verdict.critical."+plural(l, counts["Critical"]), counts["Critical"])
	case counts["High"] > 0:
		return t(l, "verdict.high."+plural(l, counts["High"]), counts["High"])
	case total > 0:
		return t(l, "verdict.other")
	}
	return t(l, "verdict.none")
}

func WriteHTML(w io.Writer, d Data) error {
	if !slices.Contains(Langs, d.Lang) {
		d.Lang = "ru"
	}
	if d.Location == nil {
		d.Location = moscow
	}
	digest := Digest(d)
	// Detectors write English; findings are shown in the report's language.
	d.Findings = localize(d.Lang, d.Findings)
	d.Resolved = localize(d.Lang, d.Resolved)
	// Findings of the cluster's platform (Kubernetes and infrastructure
	// components) are listed apart: the summary and the verdict are about
	// the applications of the team.
	var apps, platform []detectors.Finding
	for _, f := range d.Findings {
		if f.Platform {
			platform = append(platform, f)
		} else {
			apps = append(apps, f)
		}
	}
	counts := map[string]int{}
	for _, f := range apps {
		counts[f.Severity]++
	}
	var summary []sevCount
	for _, sev := range severities {
		summary = append(summary, sevCount{sev, counts[sev]})
	}
	measures := d.FSTEK != ""
	order, ok := detectors.OrderByID(d.FSTEK)
	if !ok {
		order = detectors.Orders[0]
	}
	orderTitle := order.TitleRU
	if d.Lang == "en" {
		orderTitle = order.TitleEN
	}
	rows := controls(d.Lang, order.ID, d.Findings)
	// Attack paths have their own section, highest score first.
	var attackPaths, others []detectors.Finding
	for _, f := range apps {
		if f.Detector == "attack-path" {
			attackPaths = append(attackPaths, f)
		} else {
			others = append(others, f)
		}
	}
	slices.SortStableFunc(attackPaths, func(a, b detectors.Finding) int { return b.Score - a.Score })
	err := pages[d.Lang].Execute(w, struct {
		Data
		Generated  string
		Summary    []sevCount
		Verdict    string
		Urgent     bool
		Paths      []detectors.Finding
		Groups     []group
		Platform   []detectors.Finding
		Measures   bool // the measures table is shown
		Controls   []controlRow
		Violated   int
		OrderTitle string
		Digest     string
		Draft      bool
	}{
		Data: d, Generated: fmtTime(d.Lang, d.Generated, d.Location), Summary: summary,
		Verdict: verdict(d.Lang, counts, len(apps)), Urgent: counts["Critical"]+counts["High"] > 0,
		Paths: attackPaths, Groups: groups(others), Platform: platform, Measures: measures, Controls: rows, Violated: violated(rows), OrderTitle: orderTitle,
		Digest: digest, Draft: !detectors.MappingReviewed,
	})
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	return nil
}

func violated(rows []controlRow) int {
	n := 0
	for _, r := range rows {
		if len(r.Titles) > 0 {
			n++
		}
	}
	return n
}

func localize(lang string, findings []detectors.Finding) []detectors.Finding {
	out := make([]detectors.Finding, len(findings))
	for i, f := range findings {
		out[i] = f.In(lang)
	}
	return out
}

// Digest is the SHA-256 of the data of a scan, shown in the report: the
// hash of the file itself cannot be inside it and is in the signature.
// It covers the scan, the cluster and the findings as detectors wrote them,
// so it does not depend on the language of the report.
func Digest(d Data) string {
	type finding struct {
		Fingerprint, Detector, Severity, Title, Description string
		AttackPath                                          []string
	}
	v := struct {
		ScanID        int64
		Generated     string
		Cluster       string
		Assets, Edges int
		Findings      []finding
	}{ScanID: d.ScanID, Generated: d.Generated.UTC().Format(time.RFC3339), Cluster: d.Cluster, Assets: d.Assets, Edges: d.Edges}
	for _, f := range d.Findings {
		v.Findings = append(v.Findings, finding{f.Fingerprint, f.Detector, f.Severity, f.Title, f.Description, f.AttackPath})
	}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// T translates a key of the report catalog, for other formats of the report.
func T(lang, key string, args ...any) string { return t(lang, key, args...) }

// SevLabel shows a severity in lang.
func SevLabel(lang, severity string) string { return sevLabel(lang, severity) }

// Measure is a row of the measures table.
type Measure struct {
	ID, Name, Classes string
	Titles            []string // findings violating it; none: met
	Recommendation    string
}

// Measures fills the measures table of order for findings in lang, as the
// HTML report shows it.
func Measures(lang, order string, findings []detectors.Finding) []Measure {
	var out []Measure
	for _, r := range controls(lang, order, localize(lang, findings)) {
		out = append(out, Measure(r))
	}
	return out
}

// FormatTime shows a time as the report does; loc nil is Europe/Moscow.
func FormatTime(lang string, tm time.Time, loc *time.Location) string {
	if loc == nil {
		loc = moscow
	}
	return fmtTime(lang, tm, loc)
}
