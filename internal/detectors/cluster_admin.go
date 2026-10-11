package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

func DetectClusterAdminSA(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			sa.name,
			sa.namespace,
			json_extract(e2.properties, '$.role') AS role_name
		FROM assets pods
		JOIN edges e1 ON e1.scan_id = pods.scan_id AND e1.source_uid = pods.uid AND e1.edge_type = 'USES_SA'
		JOIN assets sa ON sa.scan_id = pods.scan_id AND sa.uid = e1.target_uid
		JOIN edges e2 ON e2.scan_id = pods.scan_id AND e2.source_uid = sa.uid AND e2.edge_type = 'BOUND_TO_ROLE'
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		AND json_extract(e2.properties, '$.role') = 'cluster-admin'
		ORDER BY 1, 2, 3
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query cluster admin detection: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var namespace, workload, saName, saNamespace, roleName string
		if err := rows.Scan(&namespace, &workload, &saName, &saNamespace, &roleName); err != nil {
			return nil, fmt.Errorf("scan cluster admin result: %w", err)
		}

		findings = append(findings, Finding{
			Detector:    "cluster-admin-sa",
			Fingerprint: fingerprint("cluster-admin-sa", namespace, workload, saNamespace, saName, roleName),
			FSTEKControls: []FSTEKControl{
				{"UPD.2", "Access attribute management", "K1/K2/K3"},
				{"UPD.4", "User access management", "K1/K2/K3"},
				{"UPD.5", "Privileged user management", "K2/K3"},
				{"ZSV.1", "Software component launch control", "K1/K2/K3"},
				{"ANZ.1", "Vulnerability detection and analysis", "K2/K3"},
			},
			Recommendation: "Bind ServiceAccount to minimal role. Remove ClusterRoleBinding with cluster-admin.",
			Severity:       "Critical",
			Title:          "Workload Running with Cluster-Admin ServiceAccount",
			Description:    fmt.Sprintf("%s in namespace %s uses ServiceAccount %s bound to %s", workload, namespace, saName, roleName),
			AttackPath:     []string{fmt.Sprintf("%s/%s", namespace, workload), fmt.Sprintf("SA: %s/%s", saNamespace, saName), fmt.Sprintf("Role: %s", roleName)},
			Remediation:    fmt.Sprintf("Remove cluster-admin from ServiceAccount %s/%s", saNamespace, saName),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster admin results: %w", err)
	}

	return findings, nil
}
