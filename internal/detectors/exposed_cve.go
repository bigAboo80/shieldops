package detectors

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

func DetectExposedPodWithCVE(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	// One row per unique CVE of an exposed workload, most severe first.
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			json_extract(e_cve.properties, '$.cve_id') AS cve_id,
			json_extract(e_cve.properties, '$.severity') AS severity,
			COALESCE(json_extract(e_cve.properties, '$.package'), ''),
			COALESCE(json_extract(e_cve.properties, '$.installed'), ''),
			COALESCE(json_extract(e_cve.properties, '$.fixed'), '')
		FROM assets pods
		JOIN edges e_cve ON e_cve.scan_id = pods.scan_id AND e_cve.source_uid = pods.uid AND e_cve.edge_type = 'HAS_CVE'
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		AND EXISTS (
			SELECT 1 FROM edges e_exp
			WHERE e_exp.scan_id = pods.scan_id AND e_exp.source_uid = pods.uid AND e_exp.edge_type = 'EXPOSED_VIA'
		)
		ORDER BY 1, 2, CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END, 3
	`
	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query exposed pods with CVE: %w", err)
	}
	defer rows.Close()

	type workload struct{ namespace, name string }
	var order []workload
	cves := map[workload][]string{}
	seen := map[workload]map[string]bool{}
	fixes := map[workload][]Fix{}
	fixedIn := map[workload]map[string]string{} // CVE: "package version" fixing it
	for rows.Next() {
		var w workload
		var cveID, severity string
		var fix Fix
		if err := rows.Scan(&w.namespace, &w.name, &cveID, &severity, &fix.Package, &fix.Installed, &fix.Fixed); err != nil {
			return nil, fmt.Errorf("scan exposed CVE row: %w", err)
		}
		if seen[w] == nil {
			order = append(order, w)
			seen[w] = map[string]bool{}
			fixedIn[w] = map[string]string{}
		}
		if fix.Package != "" && !slices.Contains(fixes[w], fix) {
			fixes[w] = append(fixes[w], fix)
		}
		if fix.Fixed != "" && fixedIn[w][cveID] == "" {
			fixedIn[w][cveID] = fix.Package + " " + fix.Fixed
		}
		// Distros may rate one CVE differently; rows come most severe first, keep that one.
		if !seen[w][cveID] {
			seen[w][cveID] = true
			cves[w] = append(cves[w], fmt.Sprintf("%s(%s)", cveID, severity))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate CVE rows: %w", err)
	}

	var findings []Finding
	for _, w := range order {
		all := cves[w]
		top := all[:min(3, len(all))]
		desc := en("exposed-cve.desc", w.namespace, w.name, len(all), fmt.Sprint(top))
		var versions []string
		for _, c := range top {
			id, _, _ := strings.Cut(c, "(")
			if v := fixedIn[w][id]; v != "" && !slices.Contains(versions, v) {
				versions = append(versions, v)
			}
		}
		if len(versions) > 0 {
			desc = en("exposed-cve.descfix", w.namespace, w.name, len(all), fmt.Sprint(top), strings.Join(versions, ", "))
		}
		findings = append(findings, Finding{
			Fixes:     fixes[w],
			Targets:   []Target{workloadTarget(w.namespace, w.name)},
			Namespace: w.namespace,
			Detector:  "exposed-cve",
			// Keyed by workload only: a new CVE changes the details, not the problem.
			Fingerprint:    fingerprint("exposed-cve", w.namespace, w.name),
			FSTEKControls:  []string{"АНЗ.1", "АНЗ.2", "АНЗ.3", "ОПС.2", "ЗИС.1"},
			FSTEK117:       []string{"ЗКО.8", "ЗКС.1"},
			Recommendation: en("exposed-cve.rec"),
			Severity:       "Critical",
			Title:          en("exposed-cve.title"),
			Description:    desc,
			AttackPath: []string{
				en("path.internet"),
				fmt.Sprintf("%s/%s", w.namespace, w.name),
				en("path.cves", len(all)),
			},
			Remediation: en("exposed-cve.fix"),
		})
	}
	return findings, nil
}
