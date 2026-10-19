package detectors

import (
	"context"
	"database/sql"
	"fmt"
)

func DetectWildcardRBAC(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	query := `
		SELECT DISTINCT
			pods.namespace,
			pods.workload,
			sa.namespace,
			sa.name,
			json_extract(e2.properties, '$.role_kind'),
			json_extract(e2.properties, '$.role'),
			json_extract(e2.properties, '$.scope'),
			json_extract(e2.properties, '$.wildcard'),
			EXISTS (
				SELECT 1 FROM edges e_exp
				WHERE e_exp.scan_id = pods.scan_id AND e_exp.source_uid = pods.uid AND e_exp.edge_type = 'EXPOSED_VIA'
			),
			binding.namespace
		FROM assets pods
		JOIN edges e1 ON e1.scan_id = pods.scan_id AND e1.source_uid = pods.uid AND e1.edge_type = 'USES_SA'
		JOIN assets sa ON sa.scan_id = pods.scan_id AND sa.uid = e1.target_uid
		JOIN edges e2 ON e2.scan_id = pods.scan_id AND e2.source_uid = sa.uid AND e2.edge_type = 'WILDCARD_ROLE'
		JOIN assets binding ON binding.scan_id = pods.scan_id AND binding.uid = e2.target_uid
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		ORDER BY 1, 2, 3, 4, 5, 6, 7, 10
	`
	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("query wildcard rbac: %w", err)
	}
	defer rows.Close()

	// Replicas may differ in exposure; the finding is critical if any is exposed.
	type key struct{ namespace, workload, saNamespace, saName, roleKind, role, scope string }
	var order []key
	wildcards := map[key]string{}
	exposed := map[key]bool{}
	// A Role lives in the namespace of its RoleBinding; ClusterRoles have none.
	roleNamespace := map[key]string{}
	for rows.Next() {
		var k key
		var wildcard, bindingNamespace string
		var exp bool
		if err := rows.Scan(&k.namespace, &k.workload, &k.saNamespace, &k.saName, &k.roleKind, &k.role, &k.scope, &wildcard, &exp, &bindingNamespace); err != nil {
			return nil, fmt.Errorf("scan wildcard rbac: %w", err)
		}
		if _, ok := wildcards[k]; !ok {
			order = append(order, k)
		}
		wildcards[k] = wildcard
		exposed[k] = exposed[k] || exp
		if k.roleKind == "Role" {
			roleNamespace[k] = bindingNamespace
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wildcard rbac: %w", err)
	}

	var findings []Finding
	for _, k := range order {
		severity, path := "High", []string{}
		if exposed[k] {
			severity, path = "Critical", []string{en("path.internet")}
		}
		sa := k.saNamespace + "/" + k.saName
		findings = append(findings, Finding{
			Targets: []Target{workloadTarget(k.namespace, k.workload),
				{Kind: "ServiceAccount", Namespace: k.saNamespace, Name: k.saName},
				{Kind: k.roleKind, Namespace: roleNamespace[k], Name: k.role}},
			Namespace:      k.namespace,
			Detector:       "wildcard-rbac",
			Fingerprint:    fingerprint("wildcard-rbac", k.namespace, k.workload, k.saNamespace, k.saName, k.roleKind, k.role, k.scope),
			FSTEKControls:  []string{"УПД.2", "УПД.4", "УПД.5"},
			FSTEK117:       []string{"ЗКО.3", "УПД.2"},
			Recommendation: en("wildcard-rbac.rec"),
			Severity:       severity,
			Title:          en("wildcard-rbac.title"),
			Description: en("wildcard-rbac.desc",
				k.namespace, k.workload, sa, k.roleKind, k.role, wildcards[k], k.scope),
			AttackPath:  append(path, fmt.Sprintf("%s/%s", k.namespace, k.workload), "SA: "+sa, fmt.Sprintf("%s: %s", k.roleKind, k.role)),
			Remediation: en("wildcard-rbac.fix", k.roleKind, k.role),
		})
	}
	return findings, nil
}
