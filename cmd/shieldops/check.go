package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
)

func init() {
	commands["check"] = command{"check manifests before a rollout, e.g. in CI", runCheckCmd}
}

// errGate is returned when findings reach the -fail-on threshold; the
// command then exits with 1 without an error message.
var errGate = errors.New("findings reach the threshold")

// severityRank orders severities, Critical highest; unknown is 0.
var severityRank = map[string]int{"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

var checkFormats = []string{"text", "sarif", "gitlab", "json"}

type checkConfig struct {
	failOn, baseline, writeBaseline, format, output, lang string
}

// checked is a finding of check and where its object is defined.
type checked struct {
	detectors.Finding
	Source   inventory.Source
	Accepted bool // in the baseline: shown, but never fails the check
}

func runCheckCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: shieldops check [flags] <file|dir|->...\n\n"+
			"Checks Kubernetes manifests without a cluster. \"-\" reads stdin,\n"+
			"e.g. helm template . | shieldops check -\n\n"+
			"Exit code: 0 = below the threshold, 1 = findings reach it, 2 = bad input.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	var cc checkConfig
	fs.StringVar(&cc.failOn, "fail-on", "high", "lowest severity that fails the check: critical, high, medium, low or none")
	fs.StringVar(&cc.baseline, "baseline", "", "file of accepted findings: they are shown but do not fail the check")
	fs.StringVar(&cc.writeBaseline, "write-baseline", "", "write the current findings to this baseline file")
	fs.StringVar(&cc.format, "format", "text", "output: text, sarif, gitlab (Code Quality) or json")
	fs.StringVar(&cc.output, "output", "", "output file (empty = stdout)")
	fs.StringVar(&cc.lang, "lang", "en", "language of texts: ru or en")
	namespace := fs.String("namespace", "default", "namespace of objects without one")
	exclude := fs.String("exclude-namespaces", "", "comma-separated namespaces to skip")
	images := fs.Bool("images", false, "scan images of the manifests for CVEs with Trivy")
	trivyCmd := fs.String("trivy-cmd", "trivy", "trivy command")
	fs.Parse(args)

	if err := cc.validate(); err != nil {
		return usageError(err)
	}
	if fs.NArg() == 0 {
		return usageError(errors.New("no manifests: give files, directories or - for stdin"))
	}
	m := inventory.NewManifests(*namespace)
	for _, arg := range fs.Args() {
		if err := readManifests(m, arg); err != nil {
			return usageError(err)
		}
	}
	for _, kind := range m.Skipped {
		fmt.Fprintf(os.Stderr, "[i] not checked: kind %s\n", kind)
	}

	dir, err := os.MkdirTemp("", "shieldops-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg := scanConfig{
		db: filepath.Join(dir, "check.db"), skipTrivy: !*images, trivyCmd: *trivyCmd,
		trivyTimeout: 20 * time.Minute, keepScans: 1, log: io.Discard,
	}
	db, err := graph.Open(ctx, cfg.db)
	if err != nil {
		return err
	}
	defer db.Close()
	snap := m.Finish(csvList(*exclude))
	res, err := scanFrom(ctx, cfg, db, func(context.Context) (*inventory.Snapshot, error) { return snap, nil })
	if err != nil {
		return err
	}

	accepted, err := readBaseline(cc.baseline)
	if err != nil {
		return usageError(err)
	}
	var found []checked
	for _, f := range res.Findings {
		f = f.In(cc.lang)
		found = append(found, checked{Finding: f, Source: findingSource(m, f), Accepted: accepted[f.Fingerprint]})
	}
	slices.SortStableFunc(found, func(a, b checked) int { return severityRank[b.Severity] - severityRank[a.Severity] })

	if cc.writeBaseline != "" {
		if err := writeBaselineFile(cc.writeBaseline, found); err != nil {
			return err
		}
	}
	if err := cc.write(found); err != nil {
		return err
	}
	if cc.fails(found) {
		return errGate
	}
	return nil
}

// inputError is an error of the input: the command exits with 2.
type inputError struct{ err error }

func (e inputError) Error() string { return e.err.Error() }
func (e inputError) Unwrap() error { return e.err }

func usageError(err error) error { return inputError{err} }

func (c checkConfig) validate() error {
	if c.failOn != "none" && severityRank[titleCase(c.failOn)] == 0 {
		return fmt.Errorf("-fail-on %q: want critical, high, medium, low or none", c.failOn)
	}
	if !slices.Contains(checkFormats, c.format) {
		return fmt.Errorf("-format %q: want %s", c.format, strings.Join(checkFormats, ", "))
	}
	if c.lang != "ru" && c.lang != "en" {
		return fmt.Errorf("-lang %q: want ru or en", c.lang)
	}
	return nil
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// fails tells whether a finding outside the baseline reaches -fail-on.
func (c checkConfig) fails(found []checked) bool {
	if c.failOn == "none" {
		return false
	}
	min := severityRank[titleCase(c.failOn)]
	return slices.ContainsFunc(found, func(f checked) bool { return !f.Accepted && severityRank[f.Severity] >= min })
}

// readManifests reads a file, every .yaml, .yml and .json file under a
// directory, or stdin for "-".
func readManifests(m *inventory.Manifests, arg string) error {
	if arg == "-" {
		return m.Read(os.Stdin, "stdin")
	}
	info, err := os.Stat(arg)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return readManifestFile(m, arg)
	}
	return filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != arg && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml", ".json":
			return readManifestFile(m, path)
		}
		return nil
	})
}

func readManifestFile(m *inventory.Manifests, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return m.Read(f, filepath.ToSlash(path))
}

// findingSource is where the first target of the finding is defined.
func findingSource(m *inventory.Manifests, f detectors.Finding) inventory.Source {
	for _, t := range f.Targets {
		if src, ok := m.Sources[inventory.SourceKey(t.Kind, t.Namespace, t.Name)]; ok {
			return src
		}
	}
	return inventory.Source{}
}

// readBaseline reads fingerprints, one per line; text after them and lines
// starting with # are comments.
func readBaseline(path string) (map[string]bool, error) {
	res := map[string]bool{}
	if path == "" {
		return res, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res[strings.Fields(line)[0]] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return res, nil
}

func writeBaselineFile(path string, found []checked) error {
	var b strings.Builder
	b.WriteString("# ShieldOps baseline: accepted findings, one fingerprint per line.\n")
	for _, f := range found {
		fmt.Fprintf(&b, "%s  # %s %s: %s\n", f.Fingerprint, f.Severity, f.Title, f.Description)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func (c checkConfig) write(found []checked) error {
	w := io.Writer(os.Stdout)
	if c.output != "" {
		f, err := os.Create(c.output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	var err error
	switch c.format {
	case "sarif":
		err = writeJSON(w, sarifReport(found))
	case "gitlab":
		err = writeJSON(w, codeQuality(found))
	case "json":
		err = writeJSON(w, found)
	default:
		err = c.writeText(w, found)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", c.format, err)
	}
	if f, ok := w.(*os.File); ok && f != os.Stdout {
		return f.Close()
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// checkLabels are the labels of the text output per language.
var checkLabels = map[string]map[string]string{
	"en": {"none": "[✓] No findings", "accepted": "accepted", "why": "Why", "do": "Do", "fix": "Fix",
		"total": "%d findings, %d at or above -fail-on %s\n"},
	"ru": {"none": "[✓] Находок нет", "accepted": "принято", "why": "Почему опасно", "do": "Что сделать", "fix": "Исправление",
		"total": "Находок: %d, из них не ниже порога -fail-on %s: %d\n"},
}

func (c checkConfig) writeText(w io.Writer, found []checked) error {
	l := checkLabels[c.lang]
	if len(found) == 0 {
		_, err := fmt.Fprintln(w, l["none"])
		return err
	}
	var failing int
	for i, f := range found {
		mark := ""
		if f.Accepted {
			mark = " [" + l["accepted"] + "]"
		} else if c.failOn != "none" && severityRank[f.Severity] >= severityRank[titleCase(c.failOn)] {
			failing++
		}
		why, do := detectors.Plain(c.lang, f.Detector)
		fmt.Fprintf(w, "[%d] %s%s — %s\n    %s\n", i+1, f.Severity, mark, f.Title, f.Description)
		if f.Source.File != "" {
			fmt.Fprintf(w, "    %s:%d\n", f.Source.File, f.Source.Line)
		}
		if why != "" {
			fmt.Fprintf(w, "    %s: %s\n    %s: %s\n", l["why"], why, l["do"], do)
		} else {
			fmt.Fprintf(w, "    %s: %s\n", l["fix"], f.Remediation)
		}
		fmt.Fprintln(w)
	}
	var err error
	if c.lang == "ru" {
		_, err = fmt.Fprintf(w, l["total"], len(found), c.failOn, failing)
	} else {
		_, err = fmt.Fprintf(w, l["total"], len(found), failing, c.failOn)
	}
	return err
}

// sarif is the subset of SARIF 2.1.0 that code scanning and DefectDojo read.
type sarif struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name           string      `json:"name"`
			Version        string      `json:"version"`
			InformationURI string      `json:"informationUri"`
			Rules          []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string              `json:"ruleId"`
	Level               string              `json:"level"`
	Message             sarifMessage        `json:"message"`
	Locations           []sarifLocation     `json:"locations,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints"`
	Properties          map[string]any      `json:"properties"`
	Suppressions        []map[string]string `json:"suppressions,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// securitySeverity is the CVSS-like score GitHub code scanning sorts by.
var securitySeverity = map[string]string{"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0"}

func sarifReport(found []checked) sarif {
	var run sarifRun
	run.Tool.Driver.Name = "ShieldOps"
	run.Tool.Driver.Version = version
	run.Tool.Driver.InformationURI = "https://github.com/bigAboo80/shieldops"
	run.Results = []sarifResult{}
	rules := map[string]bool{}
	for _, f := range found {
		if !rules[f.Detector] {
			rules[f.Detector] = true
			why, do := detectors.Plain("en", f.Detector)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: f.Detector, ShortDescription: sarifMessage{f.Title}, Help: sarifMessage{strings.TrimSpace(why + " " + do)},
			})
		}
		level := "warning"
		switch f.Severity {
		case "Critical", "High":
			level = "error"
		case "Low":
			level = "note"
		}
		r := sarifResult{
			RuleID: f.Detector, Level: level,
			Message:             sarifMessage{f.Description + " Fix: " + f.Remediation},
			PartialFingerprints: map[string]string{"shieldops/v1": f.Fingerprint},
			Properties:          map[string]any{"security-severity": securitySeverity[f.Severity], "severity": f.Severity},
		}
		if f.Source.File != "" {
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = f.Source.File
			loc.PhysicalLocation.Region.StartLine = max(f.Source.Line, 1)
			r.Locations = []sarifLocation{loc}
		}
		if f.Accepted {
			r.Suppressions = []map[string]string{{"kind": "external", "justification": "in the ShieldOps baseline"}}
		}
		run.Results = append(run.Results, r)
	}
	return sarif{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run}}
}

// codeQualityIssue is an issue of the GitLab Code Quality report.
type codeQualityIssue struct {
	Description string `json:"description"`
	CheckName   string `json:"check_name"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Location    struct {
		Path  string `json:"path"`
		Lines struct {
			Begin int `json:"begin"`
		} `json:"lines"`
	} `json:"location"`
}

var codeQualitySeverity = map[string]string{"Critical": "critical", "High": "major", "Medium": "minor", "Low": "info"}

// codeQuality lists findings outside the baseline: GitLab shows every issue
// of the report in the merge request.
func codeQuality(found []checked) []codeQualityIssue {
	res := []codeQualityIssue{}
	for _, f := range found {
		if f.Accepted {
			continue
		}
		var i codeQualityIssue
		i.Description = f.Title + ": " + f.Description
		i.CheckName, i.Fingerprint = "shieldops/"+f.Detector, f.Fingerprint
		i.Severity = codeQualitySeverity[f.Severity]
		i.Location.Path = f.Source.File
		i.Location.Lines.Begin = max(f.Source.Line, 1)
		res = append(res, i)
	}
	return res
}
