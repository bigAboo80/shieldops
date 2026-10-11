package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"

	"github.com/bigAboo80/shieldops/internal/graph"
)

type trivyResult struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			PkgName         string `json:"PkgName"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type vuln struct{ id, severity, pkg, title string }

// Runner describes how to invoke trivy. Command may wrap trivy, e.g.
// "ssh scanner-host trivy", so images are pulled where bandwidth is cheap.
type Runner struct {
	Command  []string
	CacheDir string
}

// ScanImages scans every unique image once and returns HAS_CVE edges for all
// pods running it. byImage maps an image to pod UIDs. On error the edges
// found so far are returned.
func ScanImages(ctx context.Context, r Runner, byImage map[string][]string) ([]graph.Edge, error) {
	images := slices.Sorted(maps.Keys(byImage))

	// Update the vulnerability DB once, then scan every image against it.
	// A failed update is not fatal: trivy can still use a previously downloaded DB.
	if len(images) > 0 {
		if err := updateDB(ctx, r); err != nil {
			fmt.Printf("    [trivy] DB update failed, using cached DB: %v\n", err)
		}
	}

	var edges []graph.Edge
	for _, image := range images {
		fmt.Printf("    [trivy] scanning %s\n", image)
		vulns, err := scanImage(ctx, r, image)
		if errors.Is(err, exec.ErrNotFound) || ctx.Err() != nil {
			return edges, fmt.Errorf("scan %s: %w", image, err)
		}
		if err != nil {
			fmt.Printf("    [trivy] skip %s: %v\n", image, err)
			continue
		}
		for _, uid := range byImage[image] {
			for _, v := range vulns {
				edges = append(edges, graph.Edge{
					SourceUID: uid, TargetUID: uid, EdgeType: graph.EdgeHasCVE,
					Properties: map[string]string{
						"cve_id": v.id, "severity": v.severity, "package": v.pkg, "title": v.title, "image": image,
					},
				})
			}
		}
	}
	return edges, nil
}

// updateDB refreshes the vulnerability DB and the Java DB (needed for jar scanning).
func updateDB(ctx context.Context, r Runner) error {
	for _, flag := range []string{"--download-db-only", "--download-java-db-only"} {
		if _, err := r.run(ctx, "image", flag, "--no-progress", "--timeout", "30m"); err != nil {
			return err
		}
	}
	return nil
}

// scanImage runs trivy and returns CRITICAL/HIGH vulnerabilities unique by CVE ID.
func scanImage(ctx context.Context, r Runner, image string) ([]vuln, error) {
	out, err := r.run(ctx, "image", "--skip-db-update", "--skip-java-db-update",
		"--format", "json", "--severity", "CRITICAL,HIGH", "--quiet", image)
	if err != nil {
		return nil, err
	}
	return parseResult(out)
}

func (r Runner) run(ctx context.Context, args ...string) ([]byte, error) {
	if r.CacheDir != "" {
		args = append([]string{"--cache-dir", r.CacheDir}, args...)
	}
	command := r.Command
	if len(command) == 0 {
		command = []string{"trivy"}
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, command[0], slices.Concat(command[1:], args)...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

func parseResult(out []byte) ([]vuln, error) {
	var result trivyResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	var vulns []vuln
	seen := map[string]bool{}
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			if seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			vulns = append(vulns, vuln{v.VulnerabilityID, v.Severity, v.PkgName, v.Title})
		}
	}
	return vulns, nil
}
