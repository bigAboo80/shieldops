package paths

import "github.com/bigAboo80/shieldops/internal/graph"

// Weights of the risk score, the single source of the formula:
//
//	score = exposure + exploitability + privilege + blast radius, at most 100
//
// Exploitability is the worst CVE of a workload on the path; privilege is
// the strongest step of the path; blast radius is what the first workload
// reaches, counted per object and capped.
var Weights = []Weight{
	{"exposure", "internet", "the path starts in the Internet", 30},
	{"exploit", "cve-critical", "a workload on the path has a CRITICAL CVE", 25},
	{"exploit", "cve-high", "a workload on the path has a HIGH CVE (no CRITICAL)", 15},
	{"exploit", "cve-fixed", "a fixed version exists: the vulnerability is public", 5},
	{"privilege", graph.EdgeCanEscalate, "bind/escalate/impersonate or \"*\" in RBAC, or cluster-admin", 30},
	{"privilege", graph.EdgeEscapesToNode, "break out to the node", 25},
	{"privilege", graph.EdgeCanCreateWorkloads, "create pods or exec into them as another ServiceAccount", 20},
	{"privilege", graph.EdgeCanReadSecrets, "read Secrets through RBAC", 15},
	{"privilege", graph.EdgeMountsSecret, "a Secret mounted in the workload", 10},
	{"blast", "secret", "per reachable Secret", 1},
	{"blast", "namespace", "per reachable namespace", 2},
	{"blast", "node", "per reachable node", 3},
	{"blast", "max", "cap of the blast radius part", 15},
}

// Weight is one row of the formula.
type Weight struct {
	Factor, Case, Meaning string
	Points                int
}

func points(factor, c string) int {
	for _, w := range Weights {
		if w.Factor == factor && w.Case == c {
			return w.Points
		}
	}
	return 0
}

// Score explains the risk of a path, 0 to 100.
type Score struct {
	Total                                   int
	Exposure, Exploit, Privilege, BlastPart int
}

// Severity of a finding with the score.
func (s Score) Severity() string {
	switch {
	case s.Total >= 80:
		return "Critical"
	case s.Total >= 60:
		return "High"
	case s.Total >= 40:
		return "Medium"
	}
	return "Low"
}

func (g *Graph) score(steps []Step, b Blast) Score {
	var s Score
	if len(steps) > 0 && steps[0].Kind == "Internet" {
		s.Exposure = points("exposure", "internet")
	}
	var worst cveInfo
	for _, st := range steps {
		if st.Kind == "Workload" {
			c := g.cve["workload:"+st.Namespace+"/"+st.Name]
			rank := map[string]int{"HIGH": 1, "CRITICAL": 2}
			switch {
			case rank[c.Severity] > rank[worst.Severity]:
				worst = c
			case c.Severity != "" && c.Severity == worst.Severity:
				worst.Fixable = worst.Fixable || c.Fixable
			}
		}
		edge := st.Edge
		if edge == graph.EdgeBoundToRole { // cluster-admin
			edge = graph.EdgeCanEscalate
		}
		s.Privilege = max(s.Privilege, points("privilege", edge))
	}
	switch worst.Severity {
	case "CRITICAL":
		s.Exploit = points("exploit", "cve-critical")
	case "HIGH":
		s.Exploit = points("exploit", "cve-high")
	}
	if worst.Fixable {
		s.Exploit += points("exploit", "cve-fixed")
	}
	s.BlastPart = min(points("blast", "max"),
		b.Secrets*points("blast", "secret")+b.Namespaces*points("blast", "namespace")+b.Nodes*points("blast", "node"))
	s.Total = min(100, s.Exposure+s.Exploit+s.Privilege+s.BlastPart)
	return s
}
