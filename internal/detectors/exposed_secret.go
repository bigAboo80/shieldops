package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

func DetectExposedSecrets(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			secrets.name,
			svc.name
		FROM assets pods
		JOIN edges e_exp ON e_exp.scan_id = pods.scan_id AND e_exp.source_uid = pods.uid AND e_exp.edge_type = 'EXPOSED_VIA'
		JOIN assets svc ON svc.scan_id = pods.scan_id AND svc.uid = e_exp.target_uid
		JOIN edges e_sec ON e_sec.scan_id = pods.scan_id AND e_sec.source_uid = pods.uid AND e_sec.edge_type = 'MOUNTS_SECRET'
		JOIN assets secrets ON secrets.scan_id = pods.scan_id AND secrets.uid = e_sec.target_uid
		WHERE pods.scan_id = ?
		ORDER BY 1, 2, 3, 4
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query exposed secrets: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var namespace, workload, secretName, serviceName string
		if err := rows.Scan(&namespace, &workload, &secretName, &serviceName); err != nil {
			return nil, fmt.Errorf("scan exposed secret: %w", err)
		}

		findings = append(findings, Finding{
			Targets:        []Target{workloadTarget(namespace, workload), {Kind: "Secret", Namespace: namespace, Name: secretName}},
			Namespace:      namespace,
			Detector:       "exposed-secret",
			Fingerprint:    fingerprint("exposed-secret", namespace, workload, secretName, serviceName),
			FSTEKControls:  []string{"ИАФ.1", "ИАФ.3", "ИАФ.4", "ЗИС.3", "УПД.3"},
			FSTEK117:       []string{"ЗКО.3", "УПД.2", "ЗКС.1"},
			Recommendation: en("exposed-secret.rec"),
			Severity:       "High",
			Title:          en("exposed-secret.title"),
			Description:    en("exposed-secret.desc", secretName, namespace, workload, serviceName),
			AttackPath:     []string{en("path.internet"), fmt.Sprintf("Service: %s", serviceName), fmt.Sprintf("%s/%s", namespace, workload), fmt.Sprintf("Secret: %s", secretName)},
			Remediation:    en("exposed-secret.fix"),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exposed secret rows: %w", err)
	}

	return findings, nil
}
