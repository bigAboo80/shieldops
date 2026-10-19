package detectors

import (
	"context"
	"database/sql"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

func DetectPrivilegedContainer(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	workloads, err := queryFacts(ctx, db, scanID, inventory.FactPrivileged)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, w := range workloads {
		severity, path := "High", []string{w.name()}
		if w.Exposed {
			severity, path = "Critical", []string{en("path.internet"), w.name()}
		}
		var targets []Target
		for _, c := range w.values() {
			t := workloadTarget(w.Namespace, w.Workload)
			t.Container = c
			targets = append(targets, t)
		}
		findings = append(findings, Finding{
			Targets:        targets,
			Namespace:      w.Namespace,
			Detector:       "privileged-container",
			Fingerprint:    fingerprint("privileged-container", w.Namespace, w.Workload),
			FSTEKControls:  []string{"УПД.4", "УПД.5", "ОПС.1", "ЗИС.1"},
			FSTEK117:       []string{"ЗКО.5", "УПД.2"},
			Recommendation: en("privileged-container.rec"),
			Severity:       severity,
			Title:          en("privileged-container.title"),
			Description:    en("privileged-container.desc", w.name(), strings.Join(w.values(), ", ")),
			AttackPath:     append(path, en("path.privileged"), en("path.node")),
			Remediation:    en("privileged-container.fix"),
		})
	}
	return findings, nil
}
