package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

func DetectExposedPodWithCVE(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	// One row per unique CVE of an exposed workload, most severe first.
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			json_extract(e_cve.properties, '$.cve_id') AS cve_id,
			json_extract(e_cve.properties, '$.severity') AS severity
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
	for rows.Next() {
		var w workload
		var cveID, severity string
		if err := rows.Scan(&w.namespace, &w.name, &cveID, &severity); err != nil {
			return nil, fmt.Errorf("scan exposed CVE row: %w", err)
		}
		if seen[w] == nil {
			order = append(order, w)
			seen[w] = map[string]bool{}
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
		findings = append(findings, Finding{
			Detector: "exposed-cve",
			// Keyed by workload only: a new CVE changes the details, not the problem.
			Fingerprint: fingerprint("exposed-cve", w.namespace, w.name),
			FSTEKControls: []FSTEKControl{
				{"ANZ.1", "Vulnerability detection and analysis", "K1/K2/K3"},
				{"ANZ.2", "Update installation control", "K2/K3"},
				{"ANZ.3", "Software operability control", "K2/K3"},
				{"ZSV.2", "Software installation control", "K2/K3"},
				{"ZTS.1", "Security management function separation", "K1/K2/K3"},
			},
			Recommendation: "Update container image to version with patched CVE. Apply NetworkPolicy.",
			Severity:       "Critical",
			Title:          "Internet-Exposed Workload with Known CVE",
			Description:    fmt.Sprintf("%s/%s has %d CVEs, top: %v", w.namespace, w.name, len(all), top),
			AttackPath: []string{
				"Internet",
				fmt.Sprintf("%s/%s", w.namespace, w.name),
				fmt.Sprintf("%d CVEs (CRITICAL/HIGH)", len(all)),
			},
			Remediation: "Patch the vulnerability or remove internet exposure",
		})
	}
	return findings, nil
}
