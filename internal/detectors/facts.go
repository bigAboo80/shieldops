package detectors

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/bigAboo80/shieldops/internal/inventory"
)

// workloadFacts holds the facts of one workload; replicas of a Deployment
// have equal facts, so they give one entry.
type workloadFacts struct {
	Namespace, Workload string
	// Exposed: some pod of the workload is reachable via a NodePort/LoadBalancer Service.
	Exposed bool
	Facts   []inventory.Fact
}

func (w workloadFacts) name() string { return w.Namespace + "/" + w.Workload }

func (w workloadFacts) values() []string {
	var vals []string
	for _, f := range w.Facts {
		vals = append(vals, f.Value)
	}
	return vals
}

// queryFacts returns the facts of the given kinds per workload, ordered by
// namespace, workload, kind and value.
func queryFacts(ctx context.Context, db *sql.DB, scanID int64, kinds ...string) ([]workloadFacts, error) {
	query := `
		SELECT DISTINCT pods.namespace, pods.workload, f.kind, f.value,
			EXISTS (
				SELECT 1 FROM edges e
				WHERE e.scan_id = pods.scan_id AND e.source_uid = pods.uid AND e.edge_type = 'EXPOSED_VIA'
			)
		FROM assets pods
		JOIN asset_facts f ON f.scan_id = pods.scan_id AND f.uid = pods.uid
		WHERE pods.scan_id = ? AND pods.kind = 'Pod'
		AND f.kind IN (?` + strings.Repeat(",?", len(kinds)-1) + `)
		ORDER BY 1, 2, 3, 4
	`
	args := []any{scanID}
	for _, k := range kinds {
		args = append(args, k)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query facts %v: %w", kinds, err)
	}
	defer rows.Close()

	var res []workloadFacts
	for rows.Next() {
		var ns, workload string
		var f inventory.Fact
		var exposed bool
		if err := rows.Scan(&ns, &workload, &f.Kind, &f.Value, &exposed); err != nil {
			return nil, fmt.Errorf("scan fact %v: %w", kinds, err)
		}
		if n := len(res); n == 0 || res[n-1].Namespace != ns || res[n-1].Workload != workload {
			res = append(res, workloadFacts{Namespace: ns, Workload: workload})
		}
		w := &res[len(res)-1]
		w.Exposed = w.Exposed || exposed
		w.Facts = append(w.Facts, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate facts %v: %w", kinds, err)
	}
	return res, nil
}
