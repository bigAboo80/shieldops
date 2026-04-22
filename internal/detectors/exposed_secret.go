package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

func DetectExposedSecrets(ctx context.Context, db *sql.DB) ([]Finding, error) {
	query := `
		SELECT
			pods.name as pod_name,
			pods.namespace as pod_namespace,
			secrets.name as secret_name,
			svc.name as service_name
		FROM assets pods
		JOIN edges e_exp ON pods.uid = e_exp.source_uid
		JOIN edges e_sec ON pods.uid = e_sec.source_uid
		JOIN assets secrets ON secrets.uid = e_sec.target_uid
		JOIN assets svc ON svc.uid = e_exp.target_uid
		WHERE e_exp.edge_type = 'EXPOSED_VIA'
		AND e_sec.edge_type = 'MOUNTS_SECRET'
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query exposed secrets: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var podName, podNamespace, secretName, serviceName string
		if err := rows.Scan(&podName, &podNamespace, &secretName, &serviceName); err != nil {
			return nil, fmt.Errorf("scan exposed secret: %w", err)
		}

		findings = append(findings, Finding{
			FSTEKControls: []FSTEKControl{
				{"ZI.1", "User identification and authentication", "K1/K2/K3"},
				{"ZI.2", "Identifier management", "K1/K2/K3"},
				{"ZI.3", "Authentication data management", "K2/K3"},
				{"ZTS.3", "Information protection during transfer", "K1/K2/K3"},
				{"UPD.3", "Access control to protected objects", "K1/K2/K3"},
			},
			Recommendation: "Remove Secret mount from internet-exposed pod or apply NetworkPolicy.",
			Severity:    "High",
			Title:       "Secret Mounted in Internet-Exposed Pod",
			Description: fmt.Sprintf("Secret %s mounted in pod %s/%s exposed via %s", secretName, podNamespace, podName, serviceName),
			AttackPath:  []string{"Internet", fmt.Sprintf("Service: %s", serviceName), fmt.Sprintf("Pod: %s/%s", podNamespace, podName), fmt.Sprintf("Secret: %s", secretName)},
			Remediation: "Move secret to external vault or remove internet exposure",
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exposed secret rows: %w", err)
	}

	return findings, nil
}
