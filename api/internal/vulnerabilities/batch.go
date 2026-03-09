package vulnerabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"
const batchSize = 1000

// BatchScanResult is stored as the job result JSON.
type BatchScanResult struct {
	TotalPURLs          int `json:"total_purls"`
	Scanned             int `json:"scanned"`
	VulnsFound          int `json:"vulns_found"`
	ComponentsWithVulns int `json:"components_with_vulns"`
	Errors              int `json:"errors"`
}

type osvBatchRequest struct {
	Queries []osvBatchQuery `json:"queries"`
}

type osvBatchQuery struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

// RunBatchScan fetches all distinct versioned PURLs from the SBOM component
// view, queries OSV in batches of 1000, and upserts results into
// component_vulnerabilities. Progress is logged to stdout.
func RunBatchScan(ctx context.Context, db *gorm.DB) (BatchScanResult, error) {
	log.Printf("[osv-scan] starting batch vulnerability scan")

	var purls []string
	if err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT purl
		FROM sbom_component_view
		WHERE purl IS NOT NULL
		  AND purl_version IS NOT NULL
		  AND purl_version != ''
		  AND is_root = false
	`).Scan(&purls).Error; err != nil {
		return BatchScanResult{}, fmt.Errorf("fetch purls: %w", err)
	}

	log.Printf("[osv-scan] found %d distinct versioned PURLs", len(purls))

	result := BatchScanResult{TotalPURLs: len(purls)}
	now := time.Now().UTC()
	totalBatches := (len(purls) + batchSize - 1) / batchSize

	for i := 0; i < len(purls); i += batchSize {
		if err := ctx.Err(); err != nil {
			log.Printf("[osv-scan] context cancelled at batch %d", i/batchSize+1)
			return result, fmt.Errorf("scan interrupted: %w", err)
		}

		end := i + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		batch := purls[i:end]
		batchNum := i/batchSize + 1

		log.Printf("[osv-scan] batch %d/%d: querying %d PURLs (progress: %d/%d scanned)",
			batchNum, totalBatches, len(batch), result.Scanned, result.TotalPURLs)

		vulnsByIdx, err := queryOSVBatch(ctx, batch)
		if err != nil {
			log.Printf("[osv-scan] batch %d/%d: OSV query failed: %v", batchNum, totalBatches, err)
			result.Errors++
			continue
		}

		// Build rows to insert.
		rows := make([]ComponentVulnerability, 0, len(batch))
		batchVulnCount := 0
		batchComponentsWithVulns := 0
		for j, vulns := range vulnsByIdx {
			purl := batch[j]
			if len(vulns) == 0 {
				rows = append(rows, ComponentVulnerability{
					PURL:      purl,
					VulnID:    "_none",
					Source:    "osv",
					CheckedAt: now,
				})
				continue
			}
			batchComponentsWithVulns++
			seen := map[string]struct{}{}
			for _, v := range vulns {
				batchVulnCount++
				r := Result{
					VulnID:   v.ID,
					Summary:  v.Summary,
					Severity: extractSeverity(v.Affected),
					FixedIn:  extractFixedIn(v.Affected),
					Aliases:  v.Aliases,
					Source:   "osv",
				}
				appendComponentVulnRows(&rows, seen, purl, now, r)
			}
		}

		// Replace stale cache for this batch.
		if err := db.WithContext(ctx).Where("purl IN ?", batch).Delete(&ComponentVulnerability{}).Error; err != nil {
			log.Printf("[osv-scan] batch %d/%d: delete stale failed: %v", batchNum, totalBatches, err)
			result.Errors++
			continue
		}
		if len(rows) > 0 {
			if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error; err != nil {
				log.Printf("[osv-scan] batch %d/%d: insert failed: %v", batchNum, totalBatches, err)
				result.Errors++
				continue
			}
		}

		result.Scanned += len(batch)
		result.VulnsFound += batchVulnCount
		result.ComponentsWithVulns += batchComponentsWithVulns

		log.Printf("[osv-scan] batch %d/%d: done — %d vulns in %d vulnerable components",
			batchNum, totalBatches, batchVulnCount, batchComponentsWithVulns)
	}

	log.Printf("[osv-scan] finished: scanned=%d vulns_found=%d components_with_vulns=%d errors=%d",
		result.Scanned, result.VulnsFound, result.ComponentsWithVulns, result.Errors)

	return result, nil
}

func queryOSVBatch(ctx context.Context, purls []string) ([][]osvVuln, error) {
	req := osvBatchRequest{Queries: make([]osvBatchQuery, len(purls))}
	for i, p := range purls {
		req.Queries[i].Package.PURL = p
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned HTTP %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	results := make([][]osvVuln, len(batchResp.Results))
	for i, r := range batchResp.Results {
		results[i] = r.Vulns
	}
	return results, nil
}
