package detectors

import (
	"context"
	"database/sql"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

func DetectHostPath(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	workloads, err := queryFacts(ctx, db, scanID, inventory.FactHostPath)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, w := range workloads {
		for _, p := range w.values() {
			severity := "High"
			if inventory.SensitiveHostPath(p) {
				severity = "Critical"
			}
			target := workloadTarget(w.Namespace, w.Workload)
			target.Value = p
			findings = append(findings, Finding{
				Targets:        []Target{target},
				Namespace:      w.Namespace,
				Detector:       "host-path",
				Fingerprint:    fingerprint("host-path", w.Namespace, w.Workload, p),
				FSTEKControls:  []string{"УПД.3", "ОПС.1", "ЗИС.1"},
				FSTEK117:       []string{"ЗКО.5"},
				Recommendation: en("host-path.rec"),
				Severity:       severity,
				Title:          en("host-path.title"),
				Description:    en("host-path.desc", w.name(), p),
				AttackPath:     []string{w.name(), "hostPath: " + p, en("path.nodefs")},
				Remediation:    en("host-path.fix", p),
			})
		}
	}
	return findings, nil
}
