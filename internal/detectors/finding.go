package detectors

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"

	"github.com/bigAboo80/shieldops/internal/paths"
)

type Finding struct {
	Detector string
	// Namespace of the affected workload; empty for cluster-wide findings.
	Namespace string
	// Fingerprint identifies the same problem across scans: it is built from
	// the detector and the affected objects, not from volatile details.
	Fingerprint   string
	New           bool // absent from the previous finished scan
	Severity      string
	Title         string
	Description   string
	AttackPath    []string
	Remediation   string
	FSTEKControls []string // measures of order 17, designations in Controls
	FSTEK117      []string // measures of order 117 (method document of 12.04.2026)
	// Targets are the objects a fix changes, the affected workload first.
	Targets        []Target
	Recommendation string
	// Fixes are the vulnerable packages of an exposed-cve finding.
	Fixes []Fix
	// Path is the attack path of an attack-path finding, with node kinds and
	// edges; AttackPath holds the same steps as text.
	Path []paths.Step
	// Score is the risk score of an attack-path finding, 0 to 100; 0 for
	// findings of other detectors.
	Score int
	// Platform: the workload is a component of Kubernetes or of the
	// cluster's infrastructure, not an application of the team (MarkPlatform).
	Platform bool
}

// Fix is a vulnerable package and the version that fixes it.
type Fix struct {
	Package, Installed string
	Fixed              string // empty: no fix yet
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
	{"privileged-container", DetectPrivilegedContainer, false},
	{"host-namespaces", DetectHostNamespaces, false},
	{"host-path", DetectHostPath, false},
	{"no-network-policy", DetectNoNetworkPolicy, false},
	{"latest-tag", DetectLatestTag, false},
	{"wildcard-rbac", DetectWildcardRBAC, false},
	// Exploitability of paths depends on CVEs.
	{"attack-path", DetectAttackPaths, true},
}

func fingerprint(detector string, keys ...string) string {
	sum := sha256.Sum256([]byte(detector + "\x00" + strings.Join(keys, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// Target is an object a fix of a finding changes.
type Target struct {
	Kind      string // Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod, Namespace, ServiceAccount, Secret, Role, ClusterRole, ClusterRoleBinding, ...
	Namespace string // empty for cluster-scoped objects
	Name      string
	Container string // for container settings
	Value     string // what to change: a host path, a host namespace flag, an image
}

// workloadTarget turns a workload of the inventory, "Deployment/web" or
// "Pod/x", into a target. A pod without a controller is a Pod.
func workloadTarget(namespace, workload string) Target {
	kind, name, ok := strings.Cut(workload, "/")
	if !ok {
		kind, name = "Pod", workload
	}
	return Target{Kind: kind, Namespace: namespace, Name: name}
}

// ControlIDs returns the designations of the measures of order the finding
// maps to.
func (f Finding) ControlIDs(order string) []string {
	if order == "17" {
		return f.FSTEKControls
	}
	return f.FSTEK117
}
