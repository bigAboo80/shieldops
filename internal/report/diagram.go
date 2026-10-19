package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"regexp"
	"strings"

	"github.com/bigAboo80/shieldops/internal/paths"
)

//go:embed diagram.svg.tmpl
var diagramSVG string

// diagramTmpl draws a path as inline SVG. It is rendered by html/template:
// names come from the cluster. No scripts, no style attributes, only
// classes, so the strict CSP of the web interface holds.
var diagramTmpl = template.Must(template.New("diagram").Parse(diagramSVG))

// Geometry of the diagram: nodes one under another, arrows between them.
const (
	diagramW    = 360
	nodeH       = 52
	nodeGap     = 36
	maxNameRune = 40
)

// icons are 16×16 strokes per kind of node; unknown kinds get a box.
var icons = map[string]string{
	"Internet":       "M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1ZM1 8h14M8 1c2 2 3 4.5 3 7s-1 5-3 7c-2-2-3-4.5-3-7s1-5 3-7Z",
	"Ingress":        "M1 8h9M7 5l3 3-3 3M12 2h3v12h-3",
	"Service":        "M8 1l6 3.5v7L8 15l-6-3.5v-7L8 1ZM8 8l6-3.5M8 8v7M8 8 2 4.5",
	"Workload":       "M2 3h12v10H2zM2 6h12M5 9h6",
	"ServiceAccount": "M8 7a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM2 15c0-3.3 2.7-5 6-5s6 1.7 6 5",
	"Secret":         "M4 7h8v8H4zM6 7V4.5a2 2 0 0 1 4 0V7M8 10v2",
	"Node":           "M2 2h12v5H2zM2 9h12v5H2zM5 4.5h1M5 11.5h1",
	"Role":           "M8 1l6 2.5v4c0 3.6-2.6 6.5-6 7.5-3.4-1-6-3.9-6-7.5v-4L8 1Z",
	"":               "M2 2h12v12H2z",
}

// stepKinds map the kinds of text steps of older findings to icons.
var stepKinds = map[string]string{
	"SA": "ServiceAccount", "Service": "Service", "Secret": "Secret", "Ingress": "Ingress", "Node": "Node",
	"Role": "Role", "ClusterRoleBinding": "Role", "RoleBinding": "Role", "Namespace": "",
}

// workloadStep matches "ns/Deployment/web".
var workloadStep = regexp.MustCompile(`^[^/\s]+/[A-Z][A-Za-z]+/[^/\s]+$`)

type diagramNode struct {
	Y, IconY, TextX int
	Kind, Icon      string
	Caption         string // kind line
	Name, Full      string
	First, Last     bool
}

type diagramEdge struct {
	Y1, Y2, LabelY int
	Arrow          string
	Label          string
}

// Diagram renders the path of a finding as inline SVG. steps carry kinds
// and edges (attack-path findings); otherwise the text steps of attackPath
// are drawn, kinds guessed by their prefix. lang is the language of labels.
func Diagram(lang string, steps []paths.Step, attackPath []string) template.HTML {
	if !validLang(lang) {
		lang = "ru"
	}
	type node struct{ kind, caption, name, edge string }
	var ns []node
	if len(steps) > 0 {
		for _, s := range steps {
			n := node{kind: s.Kind, name: s.Label(), edge: s.Edge}
			switch s.Kind {
			case "Internet":
				n.caption, n.name = t(lang, "path.internet"), ""
			case "Workload":
				kind, name, _ := strings.Cut(s.Name, "/")
				n.caption, n.name = kind, s.Namespace+"/"+name
			case "ClusterRoleBinding", "RoleBinding":
				n.kind, n.caption, n.name = "Role", s.Kind, strings.TrimPrefix(s.Label(), s.Kind+": ")
			default:
				n.caption, n.name = s.Kind, strings.TrimPrefix(s.Label(), s.Kind+": ")
				if s.Kind == "ServiceAccount" {
					n.name = strings.TrimPrefix(s.Label(), "SA: ")
				}
			}
			ns = append(ns, n)
		}
	} else {
		for i, s := range attackPath {
			n := node{caption: "", name: s}
			if prefix, rest, ok := strings.Cut(s, ": "); ok {
				if kind, known := stepKinds[prefix]; known {
					n.kind, n.caption, n.name = kind, prefix, rest
				}
			} else if workloadStep.MatchString(s) {
				parts := strings.SplitN(s, "/", 3)
				n.kind, n.caption, n.name = "Workload", parts[1], parts[0]+"/"+parts[2]
			} else if i == 0 && (s == t("en", "path.internet") || s == t("ru", "path.internet")) {
				n.kind, n.caption, n.name = "Internet", t(lang, "path.internet"), ""
			}
			ns = append(ns, n)
		}
	}
	if len(ns) == 0 {
		return ""
	}

	var d struct {
		W, H  int
		Aria  string
		Nodes []diagramNode
		Edges []diagramEdge
	}
	d.W = diagramW
	var aria []string
	for i, n := range ns {
		y := i * (nodeH + nodeGap)
		icon, ok := icons[n.kind]
		if !ok {
			icon = icons[""]
		}
		name := n.name
		if r := []rune(name); len(r) > maxNameRune {
			name = string(r[:maxNameRune-1]) + "…"
		}
		dn := diagramNode{Y: y, IconY: y + 18, TextX: 48, Kind: cssKind(n.kind), Icon: icon, Caption: n.caption, Name: name, Full: strings.TrimSpace(n.caption + " " + n.name),
			First: i == 0, Last: i == len(ns)-1}
		d.Nodes = append(d.Nodes, dn)
		aria = append(aria, dn.Full)
		if i > 0 {
			top, bottom := y-nodeGap, y
			e := diagramEdge{Y1: top, Y2: bottom - 2, LabelY: top + nodeGap/2 + 4,
				Arrow: fmt.Sprintf("%d,%d %d,%d %d,%d", 24-5, bottom-8, 24+5, bottom-8, 24, bottom-1)}
			if n.edge != "" {
				e.Label = t(lang, "edge."+n.edge)
			}
			d.Edges = append(d.Edges, e)
		}
	}
	d.H = len(ns)*nodeH + (len(ns)-1)*nodeGap
	d.Aria = strings.Join(aria, " → ")
	var b strings.Builder
	if err := diagramTmpl.Execute(&b, d); err != nil {
		slog.Error("render path diagram", "err", err)
		return ""
	}
	return template.HTML(b.String()) // produced by html/template above
}

// cssKind is the kind as a class name suffix; only known kinds, as classes
// are not escaped by meaning.
func cssKind(kind string) string {
	if _, ok := icons[kind]; ok && kind != "" {
		return kind
	}
	return "Other"
}

func validLang(l string) bool {
	_, ok := catalog[l]
	return ok
}
