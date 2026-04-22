package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shieldops/core/internal/connector"
	"github.com/shieldops/core/pkg/trivy"
	"github.com/shieldops/core/internal/detectors"
	"github.com/shieldops/core/internal/graph"
	"github.com/shieldops/core/internal/inventory"
	"github.com/shieldops/core/internal/report"
)

func main() {
	kubeconfig := flag.String("kubeconfig", os.Getenv("HOME")+"/.kube/config", "path to kubeconfig")
	namespace := flag.String("namespace", "", "namespace to scan (empty = all)")
	dbConn := flag.String("db", "postgres://root@192.168.50.7:5432/shieldops?sslmode=disable", "PostgreSQL connection string")
	output := flag.String("output", "", "path to HTML report (e.g. report.html)")
	flag.Parse()

	fmt.Println("ShieldOps Scanner v0.1")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	client, err := connector.NewClient(*kubeconfig)
	if err != nil { fmt.Fprintf(os.Stderr, "K8s error: %v\n", err); os.Exit(1) }
	fmt.Println("[✓] Connected to K8s cluster")
	db, err := graph.InitDB(*dbConn)
	if err != nil { fmt.Fprintf(os.Stderr, "DB error: %v\n", err); os.Exit(1) }
	defer db.Close()
	fmt.Println("[✓] Connected to PostgreSQL")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	fmt.Println("\n[*] Collecting assets...")
	assets, err := inventory.CollectAll(ctx, client, *namespace)
	if err != nil { fmt.Fprintf(os.Stderr, "Inventory error: %v\n", err); os.Exit(1) }
	fmt.Printf("[✓] Discovered %d assets\n", len(assets))
	fmt.Println("[*] Building security graph...")
	for _, a := range assets {
		if err := graph.UpsertAsset(ctx, db, a.Kind, a.Name, a.Namespace, a.UID, a.Labels); err != nil {
			fmt.Fprintf(os.Stderr, "Graph error: %v\n", err); os.Exit(1)
		}
	}
	fmt.Printf("[✓] Stored %d assets in graph\n", len(assets))
	fmt.Println("[*] Building edges...")
	edgeCount, err := graph.BuildEdges(ctx, client, db, *namespace)
	if err != nil { fmt.Fprintf(os.Stderr, "Edge error: %v\n", err); os.Exit(1) }
	fmt.Printf("[✓] Created %d edges\n", edgeCount)
	fmt.Println("[*] Scanning images with Trivy...")
	trivyCtx, trivyCancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer trivyCancel()
	cveCount, err := trivy.ScanImages(trivyCtx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Trivy error: %v\n", err)
	} else {
		fmt.Printf("[✓] Found %d CVE edges\n", cveCount)
	}
	fmt.Println("\n[*] Running detectors...")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	var allFindings []detectors.Finding
	if f, err := detectors.DetectClusterAdminSA(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "Detector error: %v\n", err)
	} else { allFindings = append(allFindings, f...) }
	if f, err := detectors.DetectExposedSecrets(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "Detector error: %v\n", err)
	} else { allFindings = append(allFindings, f...) }
	if f, err := detectors.DetectExposedPodWithCVE(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "Detector error: %v\n", err)
	} else { allFindings = append(allFindings, f...) }
	if len(allFindings) == 0 {
		fmt.Println("\n[✓] No critical findings detected")
	} else {
		fmt.Printf("\n[!] Found %d findings:\n\n", len(allFindings))
		for i, f := range allFindings {
			fmt.Printf("[%d] %s — %s\n    %s\n    Path: ", i+1, f.Severity, f.Title, f.Description)
			for j, s := range f.AttackPath { if j > 0 { fmt.Print(" → ") }; fmt.Print(s) }
			fmt.Printf("\n    Fix: %s\n\n", f.Remediation)
		}
	}
	if *output != "" {
		html := report.GenerateHTML(allFindings, len(assets), edgeCount)
		if err := os.WriteFile(*output, []byte(html), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Report error: %v\n", err); os.Exit(1)
		}
		fmt.Printf("[✓] HTML report saved: %s\n", *output)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Scan completed.")
}
