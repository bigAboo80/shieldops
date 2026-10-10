package graph

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/bigAboo80/shieldops/internal/inventory"
	"github.com/lib/pq"
)

//go:embed schema.sql
var schema string

type Edge struct {
	SourceUID  string
	TargetUID  string
	EdgeType   string
	Properties map[string]string
}

// InitDB opens the database and applies the idempotent schema.
func InitDB(ctx context.Context, connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return db, nil
}

// ReplaceAssets makes the assets table an exact copy of the current scan:
// objects gone from the cluster are deleted together with their edges.
func ReplaceAssets(ctx context.Context, db *sql.DB, assets []inventory.Asset) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `TRUNCATE edges, assets`); err != nil {
		return fmt.Errorf("truncate graph: %w", err)
	}
	for _, a := range assets {
		labelsJSON, err := json.Marshal(a.Labels)
		if err != nil {
			return fmt.Errorf("marshal labels: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO assets (kind, name, namespace, uid, labels, images)
			VALUES ($1, $2, $3, $4, $5, COALESCE($6::text[], '{}'))
		`, a.Kind, a.Name, a.Namespace, a.UID, labelsJSON, pq.Array(a.Images))
		if err != nil {
			return fmt.Errorf("insert asset %s %s/%s: %w", a.Kind, a.Namespace, a.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit assets: %w", err)
	}
	return nil
}

// InsertEdge stores an edge and reports whether it was new.
func InsertEdge(ctx context.Context, db *sql.DB, e Edge) (bool, error) {
	props := e.Properties
	if props == nil {
		props = map[string]string{}
	}
	propertiesJSON, err := json.Marshal(props)
	if err != nil {
		return false, fmt.Errorf("marshal properties: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		INSERT INTO edges (source_uid, target_uid, edge_type, properties)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`, e.SourceUID, e.TargetUID, e.EdgeType, propertiesJSON)
	if err != nil {
		return false, fmt.Errorf("insert edge %s: %w", e.EdgeType, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert edge rows affected: %w", err)
	}
	return n > 0, nil
}

func StoreEdges(ctx context.Context, db *sql.DB, edges []Edge) (int, error) {
	count := 0
	for _, e := range edges {
		inserted, err := InsertEdge(ctx, db, e)
		if err != nil {
			return count, err
		}
		if inserted {
			count++
		}
	}
	return count, nil
}
