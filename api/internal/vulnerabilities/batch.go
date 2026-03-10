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
	TotalPURLs          int    `json:"total_purls"`
	Scanned             int    `json:"scanned"`
	VulnsFound          int    `json:"vulns_found"`
	ComponentsWithVulns int    `json:"components_with_vulns"`
	Errors              int    `json:"errors"`
	Phase               string `json:"phase,omitempty"` // "scanning", "enriching", or empty when done
	EnrichTotal         int    `json:"enrich_total,omitempty"`
	EnrichDone          int    `json:"enrich_done,omitempty"`
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
// The optional onProgress callback is called after each batch with the current result.
func RunBatchScan(ctx context.Context, db *gorm.DB, onProgress func(BatchScanResult)) (BatchScanResult, error) {
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

	notify := func(r BatchScanResult) {
		if onProgress != nil {
			onProgress(r)
		}
	}

	result := BatchScanResult{TotalPURLs: len(purls), Phase: "scanning"}
	notify(result)
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
			for _, v := range vulns {
				batchVulnCount++
				rows = append(rows, ComponentVulnerability{
					PURL:      purl,
					VulnID:    v.ID,
					Summary:   v.Summary,
					FixedIn:   extractFixedIn(v.Affected),
					Severity:  extractSeverity(v),
					Source:    "osv",
					CheckedAt: now,
				})
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
		notify(result)
	}

	log.Printf("[osv-scan] finished: scanned=%d vulns_found=%d components_with_vulns=%d errors=%d",
		result.Scanned, result.VulnsFound, result.ComponentsWithVulns, result.Errors)

	// Enrich vulns that are missing details (batch API returns id+modified only).
	result.Phase = "enriching"
	notify(result)
	enrichVulnDetails(ctx, db, func(done, total int) {
		result.EnrichDone = done
		result.EnrichTotal = total
		notify(result)
	})
	result.Phase = ""
	result.EnrichDone = 0
	result.EnrichTotal = 0

	return result, nil
}

// enrichVulnDetails fetches full details from /v1/vulns/{id} for any stored
// vulnerability that has no summary yet (i.e. discovered via batch scan).
// The optional onProgress callback receives (done, total) after each fetch.
func enrichVulnDetails(ctx context.Context, db *gorm.DB, onProgress func(done, total int)) {
	var missing []string
	if err := db.WithContext(ctx).
		Model(&ComponentVulnerability{}).
		Where("vuln_id <> '_none' AND (summary IS NULL OR summary = '')").
		Distinct("vuln_id").
		Pluck("vuln_id", &missing).Error; err != nil {
		log.Printf("[osv-enrich] query missing: %v", err)
		return
	}
	if len(missing) == 0 {
		return
	}
	log.Printf("[osv-enrich] fetching details for %d vulns", len(missing))
	if onProgress != nil {
		onProgress(0, len(missing))
	}

	enriched := 0
	for i, id := range missing {
		if err := ctx.Err(); err != nil {
			return
		}
		v, err := FetchVulnDetails(ctx, id)
		if err != nil {
			log.Printf("[osv-enrich] fetch %s: %v", id, err)
			continue
		}
		updates := map[string]any{
			"summary":     v.Summary,
			"description": v.Details,
			"severity":    extractSeverity(*v),
			"fixed_in":    extractFixedIn(v.Affected),
		}
		if err := db.WithContext(ctx).
			Model(&ComponentVulnerability{}).
			Where("vuln_id = ?", id).
			Updates(updates).Error; err != nil {
			log.Printf("[osv-enrich] update %s: %v", id, err)
			continue
		}
		enriched++
		if onProgress != nil {
			onProgress(i+1, len(missing))
		}
	}
	log.Printf("[osv-enrich] enriched %d/%d vulns", enriched, len(missing))
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
