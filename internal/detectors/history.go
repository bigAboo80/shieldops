package detectors

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
)

// Delta compares a scan with the previous finished one.
type Delta struct {
	Baseline bool // a previous finished scan exists
	New      int
	// Resolved holds findings of the previous scan that are gone now;
	// only Detector, Fingerprint, Severity, Title and Description are set.
	Resolved []Finding
}

// Record saves the findings of a scan, marks the ones that are new since the
// previous finished scan and lists the ones that disappeared.
//
// complete lists detectors whose results are complete in this scan. Only
// detectors complete in both scans are compared: a scan without trivy must
// not report every CVE finding as resolved, nor the next one as new.
func Record(ctx context.Context, db *sql.DB, scanID int64, findings []Finding, complete []string) (Delta, error) {
	var d Delta
	completeJSON, err := json.Marshal(complete)
	if err != nil {
		return d, fmt.Errorf("marshal complete detectors: %w", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scans SET complete_detectors = ? WHERE id = ?`, completeJSON, scanID); err != nil {
		return d, fmt.Errorf("record complete detectors: %w", err)
	}
	if err := saveFindings(ctx, db, scanID, findings); err != nil {
		return d, err
	}

	var prevID int64
	var prevCompleteJSON string
	err = db.QueryRowContext(ctx, `
		SELECT id, complete_detectors FROM scans WHERE id < ? AND status = 'done' ORDER BY id DESC LIMIT 1
	`, scanID).Scan(&prevID, &prevCompleteJSON)
	if err == sql.ErrNoRows {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("find baseline scan: %w", err)
	}
	d.Baseline = true
	var prevComplete []string
	if err := json.Unmarshal([]byte(prevCompleteJSON), &prevComplete); err != nil {
		return d, fmt.Errorf("parse complete detectors of scan %d: %w", prevID, err)
	}
	comparable := func(detector string) bool {
		return slices.Contains(complete, detector) && slices.Contains(prevComplete, detector)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT fingerprint, detector, severity, title, description FROM findings
		WHERE scan_id = ? ORDER BY detector, description
	`, prevID)
	if err != nil {
		return d, fmt.Errorf("query baseline findings: %w", err)
	}
	defer rows.Close()
	before := map[string]bool{}
	var gone []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.Fingerprint, &f.Detector, &f.Severity, &f.Title, &f.Description); err != nil {
			return d, fmt.Errorf("scan baseline finding: %w", err)
		}
		before[f.Fingerprint] = true
		gone = append(gone, f)
	}
	if err := rows.Err(); err != nil {
		return d, fmt.Errorf("iterate baseline findings: %w", err)
	}

	now := map[string]bool{}
	for i, f := range findings {
		now[f.Fingerprint] = true
		if comparable(f.Detector) && !before[f.Fingerprint] {
			findings[i].New = true
			d.New++
		}
	}
	for _, f := range gone {
		if comparable(f.Detector) && !now[f.Fingerprint] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	return d, nil
}

func saveFindings(ctx context.Context, db *sql.DB, scanID int64, findings []Finding) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	for _, f := range findings {
		_, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO findings (scan_id, fingerprint, detector, severity, title, description)
			VALUES (?, ?, ?, ?, ?, ?)
		`, scanID, f.Fingerprint, f.Detector, f.Severity, f.Title, f.Description)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.Fingerprint, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit findings: %w", err)
	}
	return nil
}
