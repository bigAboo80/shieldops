package detectors

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

func DetectExposedPodWithCVE(ctx context.Context, db *sql.DB) ([]Finding, error) {
	query := `
		SELECT
			pods.name,
			pods.namespace,
			json_agg(DISTINCT e_cve.properties ORDER BY e_cve.properties) as cves
		FROM assets pods
		JOIN edges e_exp ON pods.uid = e_exp.source_uid
		JOIN edges e_cve ON pods.uid = e_cve.source_uid
		WHERE pods.kind = 'Pod'
		AND e_exp.edge_type = 'EXPOSED_VIA'
		AND e_cve.edge_type = 'HAS_CVE'
		GROUP BY pods.name, pods.namespace
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query exposed pods with CVE: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var name, namespace, cvesJSON string
		if err := rows.Scan(&name, &namespace, &cvesJSON); err != nil {
			return nil, fmt.Errorf("scan exposed CVE row: %w", err)
		}
		var cves []map[string]string
		if err := json.Unmarshal([]byte(cvesJSON), &cves); err != nil {
			continue
		}
		// deduplicate by cve_id
		seenID := map[string]bool{}
		var unique []map[string]string
		for _, c := range cves {
			if !seenID[c["cve_id"]] {
				seenID[c["cve_id"]] = true
				unique = append(unique, c)
			}
		}
		top := unique
		if len(top) > 3 {
			top = top[:3]
		}
		var cveIDs []string
		for _, c := range top {
			cveIDs = append(cveIDs, fmt.Sprintf("%s(%s)", c["cve_id"], c["severity"]))
		}
		findings = append(findings, Finding{
			FSTEKControls: []FSTEKControl{
				{"ANZ.1", "Vulnerability detection and analysis", "K1/K2/K3"},
				{"ANZ.2", "Update installation control", "K2/K3"},
				{"ANZ.3", "Software operability control", "K2/K3"},
				{"ZSV.2", "Software installation control", "K2/K3"},
				{"ZTS.1", "Security management function separation", "K1/K2/K3"},
			},
			Recommendation: "Update container image to version with patched CVE. Apply NetworkPolicy.",
			Severity:    "Critical",
			Title:       "Internet-Exposed Pod with Known CVE",
			Description: fmt.Sprintf("Pod %s/%s has %d unique CVEs, top: %v", namespace, name, len(unique), cveIDs),
			AttackPath: []string{
				"Internet",
				fmt.Sprintf("Pod: %s/%s", namespace, name),
				fmt.Sprintf("%d unique CVEs (CRITICAL/HIGH)", len(unique)),
			},
			Remediation: "Patch the vulnerability or remove internet exposure",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate CVE rows: %w", err)
	}
	return findings, nil
}
