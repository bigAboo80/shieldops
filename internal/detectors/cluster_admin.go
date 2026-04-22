package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

type FSTEKControl struct {
	ID          string
	Description string
	Class       string
}

type Finding struct {
	Severity       string
	Title          string
	Description    string
	AttackPath     []string
	Remediation    string
	FSTEKControls  []FSTEKControl
	Recommendation string
}

func DetectClusterAdminSA(ctx context.Context, db *sql.DB) ([]Finding, error) {
	query := `
		SELECT
			pods.name as pod_name,
			pods.namespace as pod_namespace,
			sa.name as sa_name,
			sa.namespace as sa_namespace,
			e2.properties->>'role' as role_name
		FROM assets pods
		JOIN edges e1 ON pods.uid = e1.source_uid
		JOIN assets sa ON sa.uid = e1.target_uid
		JOIN edges e2 ON sa.uid = e2.source_uid
		WHERE e1.edge_type = 'USES_SA'
		AND e2.edge_type = 'BOUND_TO_ROLE'
		AND e2.properties->>'role' = 'cluster-admin'
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query cluster admin detection: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var podName, podNamespace, saName, saNamespace, roleName string
		if err := rows.Scan(&podName, &podNamespace, &saName, &saNamespace, &roleName); err != nil {
			return nil, fmt.Errorf("scan cluster admin result: %w", err)
		}

		findings = append(findings, Finding{
			FSTEKControls: []FSTEKControl{
				{"UPD.2", "Access attribute management", "K1/K2/K3"},
				{"UPD.4", "User access management", "K1/K2/K3"},
				{"UPD.5", "Privileged user management", "K2/K3"},
				{"ZSV.1", "Software component launch control", "K1/K2/K3"},
				{"ANZ.1", "Vulnerability detection and analysis", "K2/K3"},
			},
			Recommendation: "Bind ServiceAccount to minimal role. Remove ClusterRoleBinding with cluster-admin.",
			Severity:    "Critical",
			Title:       "Pod Running with Cluster-Admin ServiceAccount",
			Description: fmt.Sprintf("Pod %s in namespace %s uses ServiceAccount %s bound to %s", podName, podNamespace, saName, roleName),
			AttackPath:  []string{fmt.Sprintf("Pod: %s/%s", podNamespace, podName), fmt.Sprintf("SA: %s/%s", saNamespace, saName), fmt.Sprintf("Role: %s", roleName)},
			Remediation: fmt.Sprintf("Remove cluster-admin from ServiceAccount %s/%s", saNamespace, saName),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster admin results: %w", err)
	}

	return findings, nil
}
