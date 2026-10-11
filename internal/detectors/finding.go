package detectors

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
)

type FSTEKControl struct {
	ID          string
	Description string
	Class       string
}

type Finding struct {
	Detector string
	// Fingerprint identifies the same problem across scans: it is built from
	// the detector and the affected objects, not from volatile details.
	Fingerprint    string
	New            bool // absent from the previous finished scan
	Severity       string
	Title          string
	Description    string
	AttackPath     []string
	Remediation    string
	FSTEKControls  []FSTEKControl
	Recommendation string
}

// Detector queries the graph of one scan.
type Detector struct {
	ID     string
	Detect func(ctx context.Context, db *sql.DB, scanID int64) ([]Finding, error)
	// NeedsCVE means results are incomplete when image scanning was skipped or failed.
	NeedsCVE bool
}

// All lists every detector in report order.
var All = []Detector{
	{"cluster-admin-sa", DetectClusterAdminSA, false},
	{"exposed-secret", DetectExposedSecrets, false},
	{"exposed-cve", DetectExposedPodWithCVE, true},
}

func fingerprint(detector string, keys ...string) string {
	sum := sha256.Sum256([]byte(detector + "\x00" + strings.Join(keys, "\x00")))
	return hex.EncodeToString(sum[:16])
}
