package detectors

import (
	"context"
	"database/sql"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

func DetectLatestTag(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	workloads, err := queryFacts(ctx, db, scanID, inventory.FactLatestImage)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, w := range workloads {
		images := strings.Join(w.values(), ", ")
		var targets []Target
		for _, image := range w.values() {
			t := workloadTarget(w.Namespace, w.Workload)
			t.Value = image
			targets = append(targets, t)
		}
		findings = append(findings, Finding{
			Targets:        targets,
			Namespace:      w.Namespace,
			Detector:       "latest-tag",
			Fingerprint:    fingerprint("latest-tag", w.Namespace, w.Workload),
			FSTEKControls:  []string{"ОПС.2", "АНЗ.2", "АНЗ.3"},
			FSTEK117:       []string{"ЗКО.1", "ЗКО.7"},
			Recommendation: en("latest-tag.rec"),
			Severity:       "Low",
			Title:          en("latest-tag.title"),
			Description:    en("latest-tag.desc", w.name(), images),
			AttackPath:     []string{en("path.registry"), en("path.mutable", images), w.name()},
			Remediation:    en("latest-tag.fix"),
		})
	}
	return findings, nil
}
