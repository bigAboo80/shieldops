package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // the distroless image has no zone database

	"github.com/bigAboo80/shieldops/internal/connector"
	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	"github.com/bigAboo80/shieldops/internal/paths"
	"github.com/bigAboo80/shieldops/internal/report"
	"github.com/bigAboo80/shieldops/internal/signing"
	"github.com/bigAboo80/shieldops/pkg/trivy"
	"k8s.io/client-go/kubernetes"
)

// version of ShieldOps, shown in the CLI and the report.
const version = "0.3"

type command struct {
	summary string
	run     func(ctx context.Context, args []string) error
}

// commands of the edition. Other files add theirs in init, so an edition is
// the set of files it is built from.
var commands = map[string]command{
	"scan": {"scan the cluster once", runScanCmd},
}

func usage() string {
	var b strings.Builder
	b.WriteString("ShieldOps — Kubernetes security scanner\n\nUsage:\n")
	for _, name := range slices.Sorted(maps.Keys(commands)) {
		fmt.Fprintf(&b, "  shieldops %-6s [flags]   %s\n", name, commands[name].summary)
	}
	b.WriteString("\nRun \"shieldops <command> -h\" for flags.\n")
	return b.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	name := os.Args[1]
	if name == "help" || name == "-h" || name == "--help" {
		fmt.Print(usage())
		return
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", name, usage())
		os.Exit(2)
	}
	if err := cmd.run(ctx, os.Args[2:]); err != nil {
		os.Exit(exitCode(err))
	}
}

// exitCode reports err and returns the exit code: 1, or 2 for bad input of
// check; a failed check gate has no message, its findings are the output.
func exitCode(err error) int {
	if errors.Is(err, errGate) {
		return 1
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if errors.As(err, new(inputError)) {
		return 2
	}
	return 1
}

type scanConfig struct {
	kubeconfig, kubeContext, namespace, db string
	excludeNamespaces, platformNamespaces  string
	trivyCmd, trivyCache                   string
	skipTrivy                              bool
	trivyTimeout                           time.Duration
	keepScans                              int
	clusterName, signKeyFile               string
	// log receives the progress of a scan; nil is stdout.
	log io.Writer
}

func (c scanConfig) out() io.Writer {
	if c.log == nil {
		return os.Stdout
	}
	return c.log
}

func (c *scanConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&c.kubeconfig, "kubeconfig", defaultKubeconfig(), "path to kubeconfig (empty = in-cluster ServiceAccount)")
	fs.StringVar(&c.kubeContext, "context", "", "kubeconfig context (empty = current)")
	fs.StringVar(&c.namespace, "namespace", "", "namespace to scan (empty = all)")
	fs.StringVar(&c.excludeNamespaces, "exclude-namespaces", "", "comma-separated namespaces to skip (empty = none)")
	fs.StringVar(&c.platformNamespaces, "platform-namespaces", "", "comma-separated namespaces of cluster components, added to the defaults; \"-\" drops the defaults")
	fs.StringVar(&c.db, "db", envOr("SHIELDOPS_DB", "shieldops.db"), "SQLite database path (default $SHIELDOPS_DB)")
	fs.StringVar(&c.trivyCmd, "trivy-cmd", "trivy", `trivy command, may be wrapped, e.g. "ssh scan-host trivy"`)
	fs.StringVar(&c.trivyCache, "trivy-cache", "", "trivy cache directory (empty = trivy default)")
	fs.BoolVar(&c.skipTrivy, "skip-trivy", false, "skip image CVE scanning")
	fs.DurationVar(&c.trivyTimeout, "trivy-timeout", 20*time.Minute, "time budget for DB update and image scanning")
	fs.IntVar(&c.keepScans, "keep-scans", 100, "number of scans kept in the database")
	fs.StringVar(&c.clusterName, "cluster-name", "", "name of the cluster in reports (empty = not shown)")
	fs.StringVar(&c.signKeyFile, "sign-key-file", "", "Ed25519 key from shieldops keygen: reports get a .sig file next to them")
}

// signer loads -sign-key-file; nil when reports are not signed.
func (c scanConfig) signer() (*signing.Signer, error) {
	if c.signKeyFile == "" {
		return nil, nil
	}
	return signing.LoadSigner(c.signKeyFile)
}

// scanOutputs add report files to scan: each registers its flags and
// returns the writer, which does nothing when its flag is not set. Files of
// other editions add theirs in init.
var scanOutputs []func(fs *flag.FlagSet) func(d report.Data, signer *signing.Signer) error

// defaultKubeconfig follows kubectl, and falls back to in-cluster mode when
// no kubeconfig exists (e.g. inside a pod).
func defaultKubeconfig() string {
	if p := os.Getenv("KUBECONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".kube", "config")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// ownNamespace is the namespace ShieldOps runs in, empty outside a cluster.
func ownNamespace() string {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// csvList parses a comma-separated list, dropping blanks.
func csvList(s string) []string {
	var res []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			res = append(res, v)
		}
	}
	return res
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runScanCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var cfg scanConfig
	cfg.register(fs)
	output := fs.String("output", "", "path to HTML report (e.g. report.html)")
	lang := fs.String("lang", "ru", "language of the report: ru or en")
	timezone := fs.String("timezone", "Europe/Moscow", "time zone of the report, e.g. Europe/Moscow or UTC")
	fstek := fs.String("fstek", "", "FSTEK order of the measures table: 117 or 17 (empty = no table)")
	var outputs []func(report.Data, *signing.Signer) error
	for _, o := range scanOutputs {
		outputs = append(outputs, o(fs))
	}
	fs.Parse(args)
	signer, err := cfg.signer()
	if err != nil {
		return err
	}
	loc, err := reportLocale(*lang, *timezone)
	if err != nil {
		return err
	}
	if err := checkFSTEK(*fstek, true); err != nil {
		return err
	}

	kube, db, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	res, err := scan(ctx, cfg, kube, db)
	data := res.Data
	data.Lang, data.Location, data.FSTEK, data.Cluster = *lang, loc, *fstek, cfg.clusterName
	if len(data.Findings)+data.Assets > 0 {
		if *output != "" {
			if werr := writeReport(*output, data, signer); werr != nil {
				return werr
			}
			fmt.Printf("[✓] HTML report saved: %s\n", *output)
			if signer != nil {
				fmt.Printf("[✓] Signed: %s.sig, key %s\n", *output, signer.Fingerprint())
			}
		}
		for _, write := range outputs {
			if werr := write(data, signer); werr != nil {
				return werr
			}
		}
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if err != nil {
		return err
	}
	fmt.Println("Scan completed.")
	return nil
}

// reportLocale checks -lang and -timezone of the report.
func reportLocale(lang, timezone string) (*time.Location, error) {
	if !slices.Contains(report.Langs, lang) {
		return nil, fmt.Errorf("-lang %q: want ru or en", lang)
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil || timezone == "" {
		return nil, fmt.Errorf("-timezone %q: want a zone name such as Europe/Moscow or UTC", timezone)
	}
	return loc, nil
}

// checkFSTEK checks -fstek: the order the report maps findings to; empty
// means no measures table where allowEmpty.
func checkFSTEK(order string, allowEmpty bool) error {
	if order == "" && allowEmpty {
		return nil
	}
	if _, ok := detectors.OrderByID(order); !ok {
		return fmt.Errorf("-fstek %q: want 117 or 17", order)
	}
	return nil
}

// connect opens the cluster and the database; schemas are passed to graph.Open.
func connect(ctx context.Context, cfg scanConfig, schemas ...string) (*kubernetes.Clientset, *sql.DB, error) {
	fmt.Printf("ShieldOps Scanner v%s\n", version)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	kube, err := connector.NewClient(cfg.kubeconfig, cfg.kubeContext)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to kubernetes: %w", err)
	}
	if cfg.kubeconfig == "" {
		fmt.Println("[✓] Using in-cluster ServiceAccount")
	} else {
		fmt.Printf("[✓] Using kubeconfig %s\n", cfg.kubeconfig)
	}
	db, err := graph.Open(ctx, cfg.db, schemas...)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	fmt.Printf("[✓] Database %s\n", cfg.db)
	return kube, db, nil
}

type scanResult struct {
	report.Data
	// Recorded: the findings are saved, Complete lists the detectors whose
	// results are complete.
	Recorded bool
	Complete []string
}

// scan runs one full scan and records it. On error it returns what was
// found so far; such a scan is marked failed and never used as a baseline.
func scan(ctx context.Context, cfg scanConfig, kube kubernetes.Interface, db *sql.DB) (scanResult, error) {
	return scanFrom(ctx, cfg, db, func(ctx context.Context) (*inventory.Snapshot, error) {
		apiCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		return inventory.Collect(apiCtx, kube, cfg.namespace, csvList(cfg.excludeNamespaces))
	})
}

// scanFrom is scan of the objects collect returns: the cluster, or
// manifests in check.
func scanFrom(ctx context.Context, cfg scanConfig, db *sql.DB, collect func(context.Context) (*inventory.Snapshot, error)) (res scanResult, err error) {
	data := &res.Data
	data.Generated, data.Version = time.Now(), version
	scanID, err := graph.BeginScan(ctx, db)
	if err != nil {
		return res, err
	}
	data.ScanID = scanID
	defer func() {
		// Record the outcome even when ctx is cancelled mid-scan.
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = errors.Join(err, graph.FinishScan(finishCtx, db, scanID, err == nil), graph.PruneScans(finishCtx, db, cfg.keepScans))
	}()

	fmt.Fprintf(cfg.out(), "\n[*] Scan #%d: collecting assets...\n", scanID)
	snap, err := collect(ctx)
	if err != nil {
		return res, fmt.Errorf("inventory: %w", err)
	}
	assets := snap.Assets()
	data.Assets = len(assets)
	if err := graph.StoreAssets(ctx, db, scanID, assets); err != nil {
		return res, fmt.Errorf("store assets: %w", err)
	}
	fmt.Fprintf(cfg.out(), "[✓] Discovered %d assets\n", len(assets))

	edges := append(graph.BuildEdges(snap), graph.AttackEdges(snap)...)
	var trivyErr error
	if !cfg.skipTrivy {
		fmt.Fprintln(cfg.out(), "[*] Scanning images with Trivy...")
		trivyCtx, trivyCancel := context.WithTimeout(ctx, cfg.trivyTimeout)
		var cveEdges []graph.Edge
		cveEdges, trivyErr = trivy.ScanImages(trivyCtx, trivy.Runner{Command: strings.Fields(cfg.trivyCmd), CacheDir: cfg.trivyCache}, snap.PodsByImage())
		trivyCancel()
		if trivyErr != nil {
			trivyErr = fmt.Errorf("trivy: %w", trivyErr)
			fmt.Fprintf(os.Stderr, "%v\n", trivyErr)
		}
		edges = append(edges, cveEdges...)
		edges = append(edges, graph.LateralEdges(snap, cveEdges)...)
	}
	if data.Edges, err = graph.StoreEdges(ctx, db, scanID, edges); err != nil {
		return res, fmt.Errorf("store edges: %w", err)
	}
	fmt.Fprintf(cfg.out(), "[✓] Built graph with %d edges\n", data.Edges)
	g, err := paths.Load(ctx, db, scanID)
	if err != nil {
		return res, fmt.Errorf("load attack graph: %w", err)
	}
	if err := paths.StoreBlastRadius(ctx, db, scanID, g.BlastRadius()); err != nil {
		return res, err
	}

	var detectErrs []error
	var complete []string
	for _, d := range detectors.All {
		f, err := d.Detect(ctx, db, scanID)
		if err != nil {
			detectErrs = append(detectErrs, fmt.Errorf("detector %s: %w", d.ID, err))
			continue
		}
		data.Findings = append(data.Findings, f...)
		if d.NeedsCVE && (cfg.skipTrivy || trivyErr != nil) {
			continue
		}
		complete = append(complete, d.ID)
	}
	if err := detectors.MarkPlatform(ctx, db, scanID, data.Findings, detectors.PlatformNamespaces(cfg.platformNamespaces, ownNamespace())); err != nil {
		return res, err
	}
	if data.Delta, err = detectors.Record(ctx, db, scanID, data.Findings, complete); err != nil {
		return res, err
	}
	res.Recorded, res.Complete = true, complete
	printFindings(cfg.out(), *data)
	return res, errors.Join(append(detectErrs, trivyErr)...)
}

func printFindings(w io.Writer, d report.Data) {
	var apps, platform []detectors.Finding
	for _, f := range d.Findings {
		if f.Platform {
			platform = append(platform, f)
		} else {
			apps = append(apps, f)
		}
	}
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if len(apps) == 0 {
		fmt.Fprintln(w, "[✓] No findings in applications")
	} else {
		fmt.Fprintf(w, "[!] %d findings in applications:\n\n", len(apps))
	}
	for i, f := range apps {
		mark := ""
		if f.New {
			mark = " [NEW]"
		}
		if f.Score > 0 {
			mark += fmt.Sprintf(" [risk %d]", f.Score)
		}
		fmt.Fprintf(w, "[%d] %s%s — %s\n    %s\n    Path: %s\n    Fix: %s\n\n",
			i+1, f.Severity, mark, f.Title, f.Description, strings.Join(f.AttackPath, " → "), f.Remediation)
	}
	if len(platform) > 0 {
		fmt.Fprintf(w, "Cluster platform (Kubernetes and infrastructure components, usually set up by the cluster's provider): %d findings\n", len(platform))
		for _, f := range platform {
			fmt.Fprintf(w, "    %s — %s: %s\n", f.Severity, f.Title, f.Description)
		}
		fmt.Fprintln(w)
	}
	if d.Baseline {
		fmt.Fprintf(w, "Since previous scan: %d new, %d resolved\n", d.New, len(d.Resolved))
		for _, f := range d.Resolved {
			fmt.Fprintf(w, "    resolved: %s — %s\n", f.Title, f.Description)
		}
	}
}

// writeReport replaces the report atomically, readable by the owner only,
// and signs it when signer is set.
func writeReport(path string, d report.Data, signer *signing.Signer) error {
	if signer != nil {
		d.SignKey = signer.Fingerprint()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".report-*.html")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := report.WriteHTML(tmp, d); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("save report: %w", err)
	}
	if signer != nil {
		return signer.SignFile(path, time.Now())
	}
	return nil
}
