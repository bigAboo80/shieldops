package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
)

type Edge struct {
	SourceUID   string
	TargetUID   string
	EdgeType    string
	Properties  map[string]string
}

func InitDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

func UpsertAsset(ctx context.Context, db *sql.DB, kind, name, namespace, uid string, labels map[string]string) error {
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO assets (kind, name, namespace, uid, labels)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT(uid) DO UPDATE SET
			kind = EXCLUDED.kind,
			name = EXCLUDED.name,
			namespace = EXCLUDED.namespace,
			labels = EXCLUDED.labels
	`, kind, name, namespace, uid, labelsJSON)
	if err != nil {
		return fmt.Errorf("upsert asset: %w", err)
	}

	return nil
}

func InsertEdge(ctx context.Context, db *sql.DB, sourceUID, targetUID, edgeType string, properties map[string]string) error {
	propertiesJSON, err := json.Marshal(properties)
	if err != nil {
		return fmt.Errorf("marshal properties: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO edges (source_uid, target_uid, edge_type, properties)
		VALUES ($1, $2, $3, $4)
	`, sourceUID, targetUID, edgeType, propertiesJSON)
	if err != nil {
		return fmt.Errorf("insert edge: %w", err)
	}

	return nil
}

func QueryEdges(ctx context.Context, db *sql.DB, edgeType string) ([]Edge, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT source_uid, target_uid, edge_type, properties
		FROM edges
		WHERE edge_type = $1
	`, edgeType)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer rows.Close()

	var edges []Edge
	for rows.Next() {
		var edge Edge
		var propertiesJSON string
		if err := rows.Scan(&edge.SourceUID, &edge.TargetUID, &edge.EdgeType, &propertiesJSON); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}

		if err := json.Unmarshal([]byte(propertiesJSON), &edge.Properties); err != nil {
			return nil, fmt.Errorf("unmarshal properties: %w", err)
		}

		edges = append(edges, edge)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return edges, nil
}
