package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bigAboo80/shieldops/internal/connector"
	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	"github.com/bigAboo80/shieldops/internal/report"
	"github.com/bigAboo80/shieldops/pkg/trivy"
	"k8s.io/client-go/kubernetes"
)

const usage = `ShieldOps — Kubernetes security scanner

Usage:
  shieldops scan  [flags]   scan the cluster once
  shieldops serve [flags]   scan on a schedule and serve the latest report

Run "shieldops <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScanCmd(ctx, os.Args[2:])
	case "serve":
		err = runServeCmd(ctx, os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type scanConfig struct {
	kubeconfig, kubeContext, namespace, db string
	trivyCmd, trivyCache                   string
	skipTrivy                              bool
	trivyTimeout                           time.Duration
	keepScans                              int
}

func (c *scanConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&c.kubeconfig, "kubeconfig", defaultKubeconfig(), "path to kubeconfig (empty = in-cluster ServiceAccount)")
	fs.StringVar(&c.kubeContext, "context", "", "kubeconfig context (empty = current)")
	fs.StringVar(&c.namespace, "namespace", "", "namespace to scan (empty = all)")
	fs.StringVar(&c.db, "db", envOr("SHIELDOPS_DB", "shieldops.db"), "SQLite database path (default $SHIELDOPS_DB)")
	fs.StringVar(&c.trivyCmd, "trivy-cmd", "trivy", `trivy command, may be wrapped, e.g. "ssh scan-host trivy"`)
	fs.StringVar(&c.trivyCache, "trivy-cache", "", "trivy cache directory (empty = trivy default)")
	fs.BoolVar(&c.skipTrivy, "skip-trivy", false, "skip image CVE scanning")
	fs.DurationVar(&c.trivyTimeout, "trivy-timeout", 20*time.Minute, "time budget for DB update and image scanning")
	fs.IntVar(&c.keepScans, "keep-scans", 100, "number of scans kept in the database")
}

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
	fs.Parse(args)

	kube, db, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	data, err := scan(ctx, cfg, kube, db)
	if *output != "" && len(data.Findings)+data.Assets > 0 {
		if werr := writeReport(*output, data); werr != nil {
			return werr
		}
		fmt.Printf("[✓] HTML report saved: %s\n", *output)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if err != nil {
		return err
	}
	fmt.Println("Scan completed.")
	return nil
}

func runServeCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var cfg scanConfig
	cfg.register(fs)
	interval := fs.Duration("interval", 6*time.Hour, "time between scans")
	listen := fs.String("listen", "127.0.0.1:8080", "report address; keep it on loopback and use kubectl port-forward")
	reportPath := fs.String("report", "", "where to keep the latest report (default: next to -db)")
	fs.Parse(args)
	if *reportPath == "" {
		*reportPath = filepath.Join(filepath.Dir(cfg.db), "report.html")
	}
	if host, _, err := net.SplitHostPort(*listen); err != nil {
		return fmt.Errorf("parse -listen: %w", err)
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		fmt.Fprintf(os.Stderr, "WARNING: the report has no authentication and is served on %s\n", *listen)
	}

	kube, db, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	srv := &http.Server{Addr: *listen, Handler: reportHandler(*reportPath), ReadHeaderTimeout: 10 * time.Second}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServe() }()
	defer srv.Close()
	fmt.Printf("[✓] Serving report on http://%s, scanning every %s\n", *listen, *interval)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		data, err := scan(ctx, cfg, kube, db)
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}
		// A partial scan still shows what was found, the next one replaces it.
		if len(data.Findings)+data.Assets > 0 {
			if err := writeReport(*reportPath, data); err != nil {
				fmt.Fprintf(os.Stderr, "Report error: %v\n", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-srvErr:
			return fmt.Errorf("serve report: %w", err)
		case <-ticker.C:
		}
	}
}

// reportHandler serves only the report file. The page is static, so it gets
// the strictest headers that still allow its inline styles.
func reportHandler(path string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		body, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "First scan is still running, reload later.", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, "Cannot read report.", http.StatusInternalServerError)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.Write(body)
	})
	return mux
}

func connect(ctx context.Context, cfg scanConfig) (*kubernetes.Clientset, *sql.DB, error) {
	fmt.Println("ShieldOps Scanner v0.2")
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
	db, err := graph.Open(ctx, cfg.db)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	fmt.Printf("[✓] Database %s\n", cfg.db)
	return kube, db, nil
}

// scan runs one full scan and records it. On error it returns what was
// found so far; such a scan is marked failed and never used as a baseline.
func scan(ctx context.Context, cfg scanConfig, kube kubernetes.Interface, db *sql.DB) (data report.Data, err error) {
	data.Generated = time.Now()
	scanID, err := graph.BeginScan(ctx, db)
	if err != nil {
		return data, err
	}
	defer func() {
		// Record the outcome even when ctx is cancelled mid-scan.
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = errors.Join(err, graph.FinishScan(finishCtx, db, scanID, err == nil), graph.PruneScans(finishCtx, db, cfg.keepScans))
	}()

	apiCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	fmt.Printf("\n[*] Scan #%d: collecting assets...\n", scanID)
	snap, err := inventory.Collect(apiCtx, kube, cfg.namespace)
	if err != nil {
		return data, fmt.Errorf("inventory: %w", err)
	}
	assets := snap.Assets()
	data.Assets = len(assets)
	if err := graph.StoreAssets(ctx, db, scanID, assets); err != nil {
		return data, fmt.Errorf("store assets: %w", err)
	}
	fmt.Printf("[✓] Discovered %d assets\n", len(assets))

	edges := graph.BuildEdges(snap)
	var trivyErr error
	if !cfg.skipTrivy {
		fmt.Println("[*] Scanning images with Trivy...")
		trivyCtx, trivyCancel := context.WithTimeout(ctx, cfg.trivyTimeout)
		var cveEdges []graph.Edge
		cveEdges, trivyErr = trivy.ScanImages(trivyCtx, trivy.Runner{Command: strings.Fields(cfg.trivyCmd), CacheDir: cfg.trivyCache}, snap.PodsByImage())
		trivyCancel()
		if trivyErr != nil {
			trivyErr = fmt.Errorf("trivy: %w", trivyErr)
			fmt.Fprintf(os.Stderr, "%v\n", trivyErr)
		}
		edges = append(edges, cveEdges...)
	}
	if data.Edges, err = graph.StoreEdges(ctx, db, scanID, edges); err != nil {
		return data, fmt.Errorf("store edges: %w", err)
	}
	fmt.Printf("[✓] Built graph with %d edges\n", data.Edges)

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
	if data.Delta, err = detectors.Record(ctx, db, scanID, data.Findings, complete); err != nil {
		return data, err
	}
	printFindings(data)
	return data, errors.Join(append(detectErrs, trivyErr)...)
}

func printFindings(d report.Data) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if len(d.Findings) == 0 {
		fmt.Println("[✓] No critical findings detected")
	} else {
		fmt.Printf("[!] %d findings:\n\n", len(d.Findings))
	}
	for i, f := range d.Findings {
		mark := ""
		if f.New {
			mark = " [NEW]"
		}
		fmt.Printf("[%d] %s%s — %s\n    %s\n    Path: %s\n    Fix: %s\n\n",
			i+1, f.Severity, mark, f.Title, f.Description, strings.Join(f.AttackPath, " → "), f.Remediation)
	}
	if d.Baseline {
		fmt.Printf("Since previous scan: %d new, %d resolved\n", d.New, len(d.Resolved))
		for _, f := range d.Resolved {
			fmt.Printf("    resolved: %s — %s\n", f.Title, f.Description)
		}
	}
}

// writeReport replaces the report atomically, readable by the owner only.
func writeReport(path string, d report.Data) error {
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
	return nil
}
