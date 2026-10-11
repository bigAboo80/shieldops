package graph

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/bigAboo80/shieldops/internal/inventory"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Edge struct {
	SourceUID  string
	TargetUID  string
	EdgeType   string
	Properties map[string]string
}

// Open opens (creating if needed) the SQLite database at path and applies the
// idempotent schema. The file is created owner-only: it holds a map of the
// cluster's weaknesses.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database file: %w", err)
	}
	f.Close()

	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// One connection: a single writer, and pragmas apply to every statement.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return db, nil
}

// BeginScan registers a new scan and returns its ID.
func BeginScan(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx, `INSERT INTO scans (started_at) VALUES (?)`, now())
	if err != nil {
		return 0, fmt.Errorf("begin scan: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("begin scan id: %w", err)
	}
	return id, nil
}

// FinishScan marks a scan done or failed. Only done scans are used as a
// baseline for comparison.
func FinishScan(ctx context.Context, db *sql.DB, scanID int64, ok bool) error {
	status := "done"
	if !ok {
		status = "failed"
	}
	if _, err := db.ExecContext(ctx, `UPDATE scans SET finished_at = ?, status = ? WHERE id = ?`, now(), status, scanID); err != nil {
		return fmt.Errorf("finish scan %d: %w", scanID, err)
	}
	return nil
}

// PruneScans keeps the newest keep scans and deletes older ones with their graphs.
func PruneScans(ctx context.Context, db *sql.DB, keep int) error {
	_, err := db.ExecContext(ctx, `DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return fmt.Errorf("prune scans: %w", err)
	}
	return nil
}

func StoreAssets(ctx context.Context, db *sql.DB, scanID int64, assets []inventory.Asset) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, a := range assets {
		labels := a.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		labelsJSON, err := json.Marshal(labels)
		if err != nil {
			return fmt.Errorf("marshal labels: %w", err)
		}
		images := a.Images
		if images == nil {
			images = []string{}
		}
		imagesJSON, err := json.Marshal(images)
		if err != nil {
			return fmt.Errorf("marshal images: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO assets (scan_id, uid, kind, name, namespace, workload, labels, images)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, scanID, a.UID, a.Kind, a.Name, a.Namespace, a.Workload, labelsJSON, imagesJSON)
		if err != nil {
			return fmt.Errorf("insert asset %s %s/%s: %w", a.Kind, a.Namespace, a.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit assets: %w", err)
	}
	return nil
}

// StoreEdges stores edges of a scan and returns how many were new.
func StoreEdges(ctx context.Context, db *sql.DB, scanID int64, edges []Edge) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for _, e := range edges {
		props := e.Properties
		if props == nil {
			props = map[string]string{}
		}
		propertiesJSON, err := json.Marshal(props) // map keys are sorted, so equal edges match
		if err != nil {
			return 0, fmt.Errorf("marshal properties: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO edges (scan_id, source_uid, target_uid, edge_type, properties)
			VALUES (?, ?, ?, ?, ?)
		`, scanID, e.SourceUID, e.TargetUID, e.EdgeType, propertiesJSON)
		if err != nil {
			return 0, fmt.Errorf("insert edge %s: %w", e.EdgeType, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("insert edge rows affected: %w", err)
		}
		count += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit edges: %w", err)
	}
	return count, nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
