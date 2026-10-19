package detectors

import (
	"context"
	"database/sql"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

var hostNamespaceFlags = map[string]string{
	inventory.FactHostNetwork: "hostNetwork",
	inventory.FactHostPID:     "hostPID",
	inventory.FactHostIPC:     "hostIPC",
}

func DetectHostNamespaces(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	workloads, err := queryFacts(ctx, db, scanID, inventory.FactHostNetwork, inventory.FactHostPID, inventory.FactHostIPC)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, w := range workloads {
		var flags []string
		var targets []Target
		for _, f := range w.Facts {
			flags = append(flags, hostNamespaceFlags[f.Kind])
			t := workloadTarget(w.Namespace, w.Workload)
			t.Value = hostNamespaceFlags[f.Kind]
			targets = append(targets, t)
		}
		findings = append(findings, Finding{
			Targets:        targets,
			Namespace:      w.Namespace,
			Detector:       "host-namespaces",
			Fingerprint:    fingerprint("host-namespaces", w.Namespace, w.Workload),
			FSTEKControls:  []string{"УПД.3", "ОПС.1", "ЗИС.1"},
			FSTEK117:       []string{"ЗКО.5"},
			Recommendation: en("host-namespaces.rec"),
			Severity:       "High",
			Title:          en("host-namespaces.title"),
			Description:    en("host-namespaces.desc", w.name(), strings.Join(flags, ", ")),
			AttackPath:     []string{w.name(), en("path.hostns", strings.Join(flags, ", ")), en("path.node")},
			Remediation:    en("host-namespaces.fix", strings.Join(flags, ", ")),
		})
	}
	return findings, nil
}
