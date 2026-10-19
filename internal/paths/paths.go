// Package paths finds attack paths in the graph of a scan: from the
// Internet through what is exposed, the tokens and rights of workloads, up
// to the "crown jewels" — Secrets, nodes and the right to escalate in RBAC.
// Paths are ranked by a risk score whose weights are one table, so every
// score can be explained.
package paths

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
)

// MaxDepth bounds the edges of a path.
const MaxDepth = 6

// Node is an object of the graph. Pods are collapsed into their workload:
// replicas have the same edges, and findings are by workload.
type Node struct {
	ID        string // asset UID; "workload:<ns>/<workload>" for pods
	Kind      string // Internet, Ingress, Service, Workload, ServiceAccount, Secret, Node, ClusterRoleBinding, RoleBinding
	Name      string // workloads: "Deployment/web"
	Namespace string
}

// Key identifies the node across scans: UIDs change when an object is
// recreated, names do not.
func (n Node) Key() string {
	return n.Kind + ":" + n.Namespace + "/" + n.Name
}

// Label is the node as shown in a path, the format of the other detectors.
func (n Node) Label() string {
	switch n.Kind {
	case "Internet":
		return "Internet"
	case "Workload":
		return n.Namespace + "/" + n.Name
	case "ServiceAccount":
		return "SA: " + n.Namespace + "/" + n.Name
	}
	if n.Namespace == "" {
		return n.Kind + ": " + n.Name
	}
	return n.Kind + ": " + n.Namespace + "/" + n.Name
}

// Step is a node of a path and the edge that led to it ("" for the first).
type Step struct {
	Kind, Name, Namespace string
	Edge                  string
}

// Label is the step as shown in a path.
func (s Step) Label() string { return Node{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace}.Label() }

// Path is the shortest way from an entry to a target through one workload.
type Path struct {
	Entry, Workload, Target Node
	Steps                   []Step
	Score                   Score
}

type arc struct {
	to   string
	edge string
	// cluster: the edge grants rights over the whole cluster.
	cluster bool
}

// Graph is the attack graph of one scan.
type Graph struct {
	nodes map[string]Node
	out   map[string][]arc
	// cve is the worst CVE of each workload and whether a fix exists for one of that severity.
	cve map[string]cveInfo
}

type cveInfo struct {
	Severity string // CRITICAL or HIGH; others do not count
	Fixable  bool
}

// pathEdges are followed by attacks; BOUND_TO_ROLE only to cluster-admin.
var pathEdges = []string{
	graph.EdgeExposes, graph.EdgeRoutesTo, graph.EdgeHasToken, graph.EdgeMountsSecret, graph.EdgeEscapesToNode,
	graph.EdgeCanReadSecrets, graph.EdgeCanCreateWorkloads, graph.EdgeCanEscalate, graph.EdgeBoundToRole, graph.EdgeCanReach,
}

// Load reads the graph of a scan.
func Load(ctx context.Context, db *sql.DB, scanID int64) (*Graph, error) {
	g := &Graph{nodes: map[string]Node{}, out: map[string][]arc{}, cve: map[string]cveInfo{}}
	rows, err := db.QueryContext(ctx, `SELECT uid, kind, name, namespace, workload FROM assets WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	ids := map[string]string{} // asset UID -> node ID
	for rows.Next() {
		var uid, workload string
		var n Node
		if err := rows.Scan(&uid, &n.Kind, &n.Name, &n.Namespace, &workload); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		n.ID = uid
		if n.Kind == "Pod" {
			n = Node{ID: "workload:" + n.Namespace + "/" + workload, Kind: "Workload", Name: workload, Namespace: n.Namespace}
		}
		ids[uid] = n.ID
		g.nodes[n.ID] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}

	rows, err = db.QueryContext(ctx, `SELECT source_uid, target_uid, edge_type, properties FROM edges WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var src, dst, typ, propsJSON string
		if err := rows.Scan(&src, &dst, &typ, &propsJSON); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		var props map[string]string
		if err := json.Unmarshal([]byte(propsJSON), &props); err != nil {
			return nil, fmt.Errorf("parse edge properties: %w", err)
		}
		from, to := ids[src], ids[dst]
		switch {
		case typ == graph.EdgeHasCVE:
			g.addCVE(from, props["severity"], props["fixed"] != "")
		case typ == graph.EdgeNodeHosts, slices.Contains(pathEdges, typ):
			if typ == graph.EdgeBoundToRole && props["role"] != "cluster-admin" {
				continue
			}
			cluster := typ == graph.EdgeBoundToRole || (typ == graph.EdgeCanEscalate && props["scope"] == "cluster")
			a := arc{to: to, edge: typ, cluster: cluster}
			if from != to && !slices.Contains(g.out[from], a) {
				g.out[from] = append(g.out[from], a)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edges: %w", err)
	}
	// Map order is random: sort arcs, so paths and their order are stable.
	for id := range g.out {
		slices.SortFunc(g.out[id], func(a, b arc) int {
			na, nb := g.nodes[a.to], g.nodes[b.to]
			return cmp.Or(cmp.Compare(na.Kind, nb.Kind), cmp.Compare(na.Namespace, nb.Namespace), cmp.Compare(na.Name, nb.Name), cmp.Compare(a.edge, b.edge))
		})
	}
	return g, nil
}

func (g *Graph) addCVE(id, severity string, fixable bool) {
	if severity != "CRITICAL" && severity != "HIGH" {
		return
	}
	cur, ok := g.cve[id]
	switch {
	case !ok, severity == "CRITICAL" && cur.Severity == "HIGH":
		g.cve[id] = cveInfo{severity, fixable}
	case severity == cur.Severity:
		cur.Fixable = cur.Fixable || fixable
		g.cve[id] = cur
	}
}

// target tells whether the attack may stop at n: a Secret, a node, or a
// binding that hands over RBAC (reached only by CAN_ESCALATE or cluster-admin).
func target(n Node) bool {
	switch n.Kind {
	case "Secret", "Node", "ClusterRoleBinding", "RoleBinding":
		return true
	}
	return false
}

// entrance is the way from the Internet to a workload, through a Service
// or an Ingress and its Service.
type entrance struct {
	workload string
	steps    []Step
}

// Paths returns, for every workload reachable from the Internet and every
// target reachable from it, the shortest path, worst first.
func (g *Graph) Paths() []Path {
	if _, ok := g.nodes[inventory.InternetUID]; !ok {
		return nil
	}
	blast := g.blastRadius()
	var out []Path
	for _, ent := range g.entrances() {
		w := g.nodes[ent.workload]
		for _, tail := range g.bfs(ent.workload, MaxDepth-(len(ent.steps)-1)) {
			steps := append(slices.Clone(ent.steps), tail...)
			last := steps[len(steps)-1]
			p := Path{
				Entry:    g.nodes[inventory.InternetUID],
				Workload: w,
				Target:   Node{Kind: last.Kind, Name: last.Name, Namespace: last.Namespace},
				Steps:    steps,
			}
			p.Score = g.score(steps, blast[ent.workload])
			out = append(out, p)
		}
	}
	slices.SortStableFunc(out, func(a, b Path) int { return cmp.Compare(b.Score.Total, a.Score.Total) })
	return out
}

// entrances are the workloads reached from the Internet, by the shortest way.
func (g *Graph) entrances() []entrance {
	internet := g.nodes[inventory.InternetUID]
	start := []Step{{Kind: internet.Kind, Name: internet.Name}}
	var out []entrance
	seen := map[string]bool{inventory.InternetUID: true}
	queue := []entrance{{inventory.InternetUID, start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, a := range g.out[cur.workload] {
			if seen[a.to] || (a.edge != "EXPOSES" && a.edge != "ROUTES_TO") {
				continue
			}
			seen[a.to] = true
			n := g.nodes[a.to]
			next := entrance{a.to, append(slices.Clone(cur.steps), step(n, a.edge))}
			if n.Kind == "Workload" {
				out = append(out, next)
			} else {
				queue = append(queue, next)
			}
		}
	}
	return out
}

func step(n Node, edge string) Step {
	return Step{Kind: n.Kind, Name: n.Name, Namespace: n.Namespace, Edge: edge}
}

// bfs returns the shortest path from a workload to every target within
// depth edges, without the start; it never goes back to the entrances.
// Targets end a path: what lies behind a node or cluster-admin counts in
// the blast radius instead of giving a path of its own.
func (g *Graph) bfs(from string, depth int) [][]Step {
	type item struct {
		id    string
		steps []Step
	}
	seen := map[string]bool{from: true}
	queue := []item{{from, nil}}
	var out [][]Step
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.steps) == depth {
			continue
		}
		for _, a := range g.out[cur.id] {
			if seen[a.to] || a.edge == "EXPOSES" || a.edge == "ROUTES_TO" || a.edge == graph.EdgeNodeHosts {
				continue
			}
			seen[a.to] = true
			n := g.nodes[a.to]
			next := item{a.to, append(slices.Clone(cur.steps), step(n, a.edge))}
			if target(n) {
				out = append(out, next.steps)
				continue
			}
			queue = append(queue, next)
		}
	}
	return out
}

// Blast is the blast radius of a workload: what an attacker inside it can
// reach, through nodes and cluster-wide rights too.
type Blast struct {
	Namespace, Workload        string
	Secrets, Namespaces, Nodes int
}

// BlastRadius returns the blast radius of every workload, by namespace and name.
func (g *Graph) BlastRadius() []Blast {
	var out []Blast
	for id, b := range g.blastRadius() {
		n := g.nodes[id]
		b.Namespace, b.Workload = n.Namespace, n.Name
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b Blast) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Workload, b.Workload))
	})
	return out
}

func (g *Graph) blastRadius() map[string]Blast {
	var all Blast
	allNS := map[string]bool{}
	for _, n := range g.nodes {
		all.count(n, allNS)
	}
	all.Namespaces = len(allNS)

	out := map[string]Blast{}
	for id, n := range g.nodes {
		if n.Kind != "Workload" {
			continue
		}
		var b Blast
		ns := map[string]bool{}
		seen := map[string]bool{id: true}
		queue := []string{id}
		for len(queue) > 0 && b != all {
			cur := queue[0]
			queue = queue[1:]
			for _, a := range g.out[cur] {
				if a.cluster { // cluster-admin or "*" over the cluster: everything
					b = all
					break
				}
				if seen[a.to] || a.edge == "EXPOSES" || a.edge == "ROUTES_TO" {
					continue
				}
				seen[a.to] = true
				b.count(g.nodes[a.to], ns)
				queue = append(queue, a.to)
			}
			if b != all {
				b.Namespaces = len(ns)
			}
		}
		out[id] = b
	}
	return out
}

func (b *Blast) count(n Node, namespaces map[string]bool) {
	switch n.Kind {
	case "Secret":
		b.Secrets++
	case "Node":
		b.Nodes++
	}
	if n.Namespace != "" {
		namespaces[n.Namespace] = true
	}
}

// StoreBlastRadius saves the blast radius of the workloads of a scan.
func StoreBlastRadius(ctx context.Context, db *sql.DB, scanID int64, blast []Blast) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	for _, b := range blast {
		_, err := tx.ExecContext(ctx, `
			INSERT OR REPLACE INTO blast_radius (scan_id, namespace, workload, secrets, namespaces, nodes) VALUES (?, ?, ?, ?, ?, ?)
		`, scanID, b.Namespace, b.Workload, b.Secrets, b.Namespaces, b.Nodes)
		if err != nil {
			return fmt.Errorf("insert blast radius of %s/%s: %w", b.Namespace, b.Workload, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blast radius: %w", err)
	}
	return nil
}
