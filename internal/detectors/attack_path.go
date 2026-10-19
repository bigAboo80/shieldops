package detectors

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/paths"
)

// DetectAttackPaths reports the attack paths of the scan, worst first: one
// finding per workload reachable from the Internet and target it leads to.
// Secrets read through RBAC rights are one finding per workload and
// ServiceAccount: a controller that may read every Secret of the cluster
// would otherwise give a finding per Secret, and one change of its rights
// fixes them all.
func DetectAttackPaths(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error) {
	g, err := paths.Load(ctx, db, scanID)
	if err != nil {
		return nil, err
	}
	var order []string
	groups := map[string][]paths.Path{}
	for _, p := range g.Paths() {
		key := p.Entry.Key() + "\x00" + p.Target.Key() + "\x00" + p.Workload.ID
		if via, ok := readsSecrets(p); ok {
			key = p.Entry.Key() + "\x00secrets-via\x00" + via.Label() + "\x00" + p.Workload.ID
		}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], p)
	}
	findings := make([]Finding, 0, len(order))
	for _, key := range order {
		findings = append(findings, pathFinding(groups[key]))
	}
	return findings, nil
}

// readsSecrets returns the step whose RBAC rights let the path read its
// Secret, usually the ServiceAccount of the workload.
func readsSecrets(p paths.Path) (paths.Step, bool) {
	n := len(p.Steps)
	if n < 2 || p.Steps[n-1].Edge != graph.EdgeCanReadSecrets {
		return paths.Step{}, false
	}
	return p.Steps[n-2], true
}

// pathFinding is the finding of the paths of one group, the worst first.
func pathFinding(group []paths.Path) Finding {
	p := group[0]
	steps := slices.Clone(p.Steps)
	w := p.Workload
	// Keyed by entry, target and the first workload: other steps may
	// change between scans while the path stays the same problem.
	fp := fingerprint("attack-path", p.Entry.Key(), p.Target.Key(), w.Namespace, w.Name)
	desc := en("attack-path.desc", w.Namespace, w.Name, p.Target.Label(), len(p.Steps)-1, p.Score.Total)
	if via, ok := readsSecrets(p); ok {
		fp = fingerprint("attack-path", p.Entry.Key(), "secrets-via:"+via.Label(), w.Namespace, w.Name)
		if len(group) > 1 {
			last := &steps[len(steps)-1]
			last.Name += fmt.Sprintf(" +%d", len(group)-1)
			desc = en("attack-path.descmany", w.Namespace, w.Name, len(group), via.Label(), p.Score.Total)
		}
	}
	var labels []string
	for _, s := range steps {
		labels = append(labels, s.Label())
	}
	c17, c117 := pathControls(p)
	return Finding{
		Targets:        []Target{workloadTarget(w.Namespace, w.Name)},
		Namespace:      w.Namespace,
		Detector:       "attack-path",
		Fingerprint:    fp,
		FSTEKControls:  c17,
		FSTEK117:       c117,
		Recommendation: en("attack-path.rec"),
		Severity:       p.Score.Severity(),
		Title:          en("attack-path.title", p.Target.Kind),
		Description:    desc,
		AttackPath:     labels,
		Remediation:    en("attack-path.fix"),
		Path:           steps,
		Score:          p.Score.Total,
	}
}

// pathControls maps the steps of a path to the measures they violate, in
// the order of DetectorControls. To be reviewed by a FSTEK expert.
func pathControls(p paths.Path) (order17, order117 []string) {
	var violated []string // measures of order 117
	for _, s := range p.Steps {
		switch s.Edge {
		case graph.EdgeExposes, graph.EdgeCanReach:
			violated = append(violated, "МСЭ.1")
		case graph.EdgeHasToken, graph.EdgeMountsSecret, graph.EdgeCanReadSecrets, graph.EdgeCanCreateWorkloads, graph.EdgeCanEscalate, graph.EdgeBoundToRole:
			violated = append(violated, "ЗКО.3")
		case graph.EdgeEscapesToNode:
			violated = append(violated, "ЗКО.5")
		}
	}
	if p.Score.Exploit > 0 {
		violated = append(violated, "ЗКО.8")
	}
	// The measures of order 17 at the same positions.
	all17, all117 := DetectorControls("attack-path", "17"), DetectorControls("attack-path", "117")
	for i, id := range all117 {
		if slices.Contains(violated, id) {
			order117 = append(order117, id)
			order17 = append(order17, all17[i])
		}
	}
	return order17, order117
}
