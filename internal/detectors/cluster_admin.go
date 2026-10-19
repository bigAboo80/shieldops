package detectors

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func DetectClusterAdminSA(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			sa.name,
			sa.namespace,
			json_extract(e2.properties, '$.role') AS role_name,
			binding.name
		FROM assets pods
		JOIN edges e1 ON e1.scan_id = pods.scan_id AND e1.source_uid = pods.uid AND e1.edge_type = 'USES_SA'
		JOIN assets sa ON sa.scan_id = pods.scan_id AND sa.uid = e1.target_uid
		JOIN edges e2 ON e2.scan_id = pods.scan_id AND e2.source_uid = sa.uid AND e2.edge_type = 'BOUND_TO_ROLE'
		JOIN assets binding ON binding.scan_id = pods.scan_id AND binding.uid = e2.target_uid
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		AND json_extract(e2.properties, '$.role') = 'cluster-admin'
		ORDER BY 1, 2, 3, 4, 5, 6
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query cluster admin detection: %w", err)
	}
	defer rows.Close()

	// One finding per workload and ServiceAccount; every binding to
	// cluster-admin is a target of the fix.
	var findings []Finding
	var prev string
	for rows.Next() {
		var namespace, workload, saName, saNamespace, roleName, binding string
		if err := rows.Scan(&namespace, &workload, &saName, &saNamespace, &roleName, &binding); err != nil {
			return nil, fmt.Errorf("scan cluster admin result: %w", err)
		}
		bindingTarget := Target{Kind: "ClusterRoleBinding", Name: binding}
		if key := strings.Join([]string{namespace, workload, saName, saNamespace, roleName}, "\x00"); key == prev {
			last := &findings[len(findings)-1]
			last.Targets = append(last.Targets, bindingTarget)
			continue
		} else {
			prev = key
		}

		findings = append(findings, Finding{
			Targets:        []Target{workloadTarget(namespace, workload), {Kind: "ServiceAccount", Namespace: saNamespace, Name: saName}, bindingTarget},
			Namespace:      namespace,
			Detector:       "cluster-admin-sa",
			Fingerprint:    fingerprint("cluster-admin-sa", namespace, workload, saNamespace, saName, roleName),
			FSTEKControls:  []string{"УПД.2", "УПД.4", "УПД.5", "ОПС.1", "АНЗ.1"},
			FSTEK117:       []string{"ЗКО.3", "УПД.2"},
			Recommendation: en("cluster-admin-sa.rec"),
			Severity:       "Critical",
			Title:          en("cluster-admin-sa.title"),
			Description:    en("cluster-admin-sa.desc", workload, namespace, saName, roleName),
			AttackPath:     []string{fmt.Sprintf("%s/%s", namespace, workload), fmt.Sprintf("SA: %s/%s", saNamespace, saName), fmt.Sprintf("Role: %s", roleName)},
			Remediation:    en("cluster-admin-sa.fix", saNamespace, saName),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster admin results: %w", err)
	}

	return findings, nil
}
