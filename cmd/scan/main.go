package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bigAboo80/shieldops/internal/connector"
	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/graph"
	"github.com/bigAboo80/shieldops/internal/inventory"
	"github.com/bigAboo80/shieldops/internal/report"
	"github.com/bigAboo80/shieldops/pkg/trivy"
)

func main() {
	home, _ := os.UserHomeDir()
	defaultKubeconfig := os.Getenv("KUBECONFIG")
	if defaultKubeconfig == "" {
		defaultKubeconfig = filepath.Join(home, ".kube", "config")
	}
	kubeconfig := flag.String("kubeconfig", defaultKubeconfig, "path to kubeconfig")
	kubeContext := flag.String("context", "", "kubeconfig context (empty = current)")
	namespace := flag.String("namespace", "", "namespace to scan (empty = all)")
	dbConn := flag.String("db", os.Getenv("SHIELDOPS_DB"), "PostgreSQL connection string (default $SHIELDOPS_DB)")
	output := flag.String("output", "", "path to HTML report (e.g. report.html)")
	trivyCmd := flag.String("trivy-cmd", "trivy", `trivy command, may be wrapped, e.g. "ssh scan-host trivy"`)
	trivyCache := flag.String("trivy-cache", "", "trivy cache directory (empty = trivy default)")
	skipTrivy := flag.Bool("skip-trivy", false, "skip image CVE scanning")
	trivyTimeout := flag.Duration("trivy-timeout", 20*time.Minute, "time budget for DB update and image scanning")
	flag.Parse()

	if *dbConn == "" {
		fail("Config error", fmt.Errorf("set -db or SHIELDOPS_DB"))
	}

	fmt.Println("ShieldOps Scanner v0.1")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	clients, err := connector.NewClients(*kubeconfig, *kubeContext)
	if err != nil {
		fail("K8s error", err)
	}
	fmt.Println("[✓] Connected to K8s cluster")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := graph.InitDB(ctx, *dbConn)
	if err != nil {
		fail("DB error", err)
	}
	defer db.Close()
	fmt.Println("[✓] Connected to PostgreSQL")

	fmt.Println("\n[*] Collecting assets...")
	snap, err := inventory.Collect(ctx, clients, *namespace)
	if err != nil {
		fail("Inventory error", err)
	}
	assets := snap.Assets()
	fmt.Printf("[✓] Discovered %d assets\n", len(assets))

	fmt.Println("[*] Building security graph...")
	if err := graph.ReplaceAssets(ctx, db, assets); err != nil {
		fail("Graph error", err)
	}
	fmt.Printf("[✓] Stored %d assets in graph\n", len(assets))
	edgeCount, err := graph.StoreEdges(ctx, db, graph.BuildEdges(snap))
	if err != nil {
		fail("Edge error", err)
	}
	fmt.Printf("[✓] Created %d edges\n", edgeCount)

	if !*skipTrivy {
		fmt.Println("[*] Scanning images with Trivy...")
		trivyCtx, trivyCancel := context.WithTimeout(context.Background(), *trivyTimeout)
		cveCount, err := trivy.ScanImages(trivyCtx, db, trivy.Runner{Command: strings.Fields(*trivyCmd), CacheDir: *trivyCache})
		trivyCancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Trivy error: %v\n", err)
		}
		fmt.Printf("[✓] Found %d CVE edges\n", cveCount)
	}

	fmt.Println("\n[*] Running detectors...")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	var allFindings []detectors.Finding
	failed := false
	for _, detect := range []func(context.Context, *sql.DB) ([]detectors.Finding, error){
		detectors.DetectClusterAdminSA,
		detectors.DetectExposedSecrets,
		detectors.DetectExposedPodWithCVE,
	} {
		f, err := detect(ctx, db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Detector error: %v\n", err)
			failed = true
			continue
		}
		allFindings = append(allFindings, f...)
	}

	if len(allFindings) == 0 {
		fmt.Println("\n[✓] No critical findings detected")
	} else {
		fmt.Printf("\n[!] Found %d findings:\n\n", len(allFindings))
		for i, f := range allFindings {
			fmt.Printf("[%d] %s — %s\n    %s\n    Path: ", i+1, f.Severity, f.Title, f.Description)
			for j, s := range f.AttackPath {
				if j > 0 {
					fmt.Print(" → ")
				}
				fmt.Print(s)
			}
			fmt.Printf("\n    Fix: %s\n\n", f.Remediation)
		}
	}
	if *output != "" {
		html := report.GenerateHTML(allFindings, len(assets), edgeCount)
		if err := os.WriteFile(*output, []byte(html), 0644); err != nil {
			fail("Report error", err)
		}
		fmt.Printf("[✓] HTML report saved: %s\n", *output)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if failed {
		fmt.Println("Scan completed with detector errors.")
		os.Exit(1)
	}
	fmt.Println("Scan completed.")
}

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}
