package trivy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/shieldops/core/internal/graph"
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

func ScanImages(ctx context.Context, db *sql.DB) (int, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT uid, labels->>'image' as image
		FROM assets
		WHERE kind = 'Pod'
		AND labels->>'image' IS NOT NULL
		AND labels->>'image' != ''
	`)
	if err != nil {
		return 0, fmt.Errorf("query pod images: %w", err)
	}
	defer rows.Close()

	type podImage struct{ uid, image string }
	var pods []podImage
	seen := map[string]bool{}
	for rows.Next() {
		var p podImage
		if err := rows.Scan(&p.uid, &p.image); err != nil {
			continue
		}
		if !seen[p.image] {
			seen[p.image] = true
			pods = append(pods, p)
		}
	}

	edgeCount := 0
	for _, p := range pods {
		fmt.Printf("    [trivy] scanning %s\n", p.image)
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx,
			"trivy", "image",
			"--cache-dir", "/tmp/trivy-cache",
			"--format", "json",
			"--severity", "CRITICAL,HIGH",
			"--quiet",
			p.image,
		)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			fmt.Printf("    [trivy] skip %s: %v — %s\n", p.image, err, stderr.String())
			continue
		}

		var result trivyResult
		if err := json.Unmarshal(out, &result); err != nil {
			continue
		}

		// deduplicate CVEs per image
		seenCVE := map[string]bool{}
		for _, r := range result.Results {
			for _, v := range r.Vulnerabilities {
				if seenCVE[v.VulnerabilityID] {
					continue
				}
				seenCVE[v.VulnerabilityID] = true
				props := map[string]string{
					"cve_id":   v.VulnerabilityID,
					"severity": v.Severity,
					"package":  v.PkgName,
					"title":    v.Title,
				}
				if err := graph.InsertEdge(ctx, db, p.uid, p.uid, "HAS_CVE", props); err != nil {
					continue
				}
				edgeCount++
			}
		}
	}
	return edgeCount, nil
}
