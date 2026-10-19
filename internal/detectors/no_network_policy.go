package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

// DetectNoNetworkPolicy reports namespaces where some pods are selected by no
// NetworkPolicy, one finding per namespace.
func DetectNoNetworkPolicy(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	query := `
		SELECT pods.namespace, COUNT(DISTINCT pods.workload), COUNT(DISTINCT pods.uid)
		FROM assets pods
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		AND NOT EXISTS (
			SELECT 1 FROM edges e
			WHERE e.scan_id = pods.scan_id AND e.source_uid = pods.uid AND e.edge_type = 'SELECTED_BY'
		)
		GROUP BY pods.namespace
		ORDER BY 1
	`
	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query unprotected namespaces: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var namespace string
		var workloads, pods int
		if err := rows.Scan(&namespace, &workloads, &pods); err != nil {
			return nil, fmt.Errorf("scan unprotected namespace: %w", err)
		}
		findings = append(findings, Finding{
			Targets:        []Target{{Kind: "Namespace", Name: namespace}},
			Namespace:      namespace,
			Detector:       "no-network-policy",
			Fingerprint:    fingerprint("no-network-policy", namespace),
			FSTEKControls:  []string{"УПД.3", "ЗИС.3", "ЗИС.17"},
			FSTEK117:       []string{"МСЭ.1", "МСЭ.3"},
			Recommendation: en("no-network-policy.rec"),
			Severity:       "Medium",
			Title:          en("no-network-policy.title"),
			Description:    en("no-network-policy.desc", namespace, workloads, pods),
			AttackPath:     []string{en("path.anypod"), fmt.Sprintf("Namespace: %s", namespace), en("path.traffic")},
			Remediation:    en("no-network-policy.fix", namespace),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unprotected namespaces: %w", err)
	}
	return findings, nil
}
