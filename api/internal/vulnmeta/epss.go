package vulnmeta

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// epssFeedURL is FIRST.org's daily Exploit Prediction Scoring System
// snapshot — a gzipped CSV of every CVE's 30-day exploitation
// probability. ~250k rows; refreshed once per UTC day.
const epssFeedURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// epssClient gets a longer timeout than the metadata fetchers — the
// gzipped payload is ~5 MB and FIRST.org occasionally throttles bulk
// downloads, so we'd rather wait than fail and force a full retry.
var epssClient = &http.Client{Timeout: 5 * time.Minute}

// IngestEPSS pulls the daily CSV, parses score + percentile per CVE,
// and replaces epss_entries inside a transaction. Streams through
// gzip+CSV so peak memory stays bounded at ~the batch size below
// instead of holding the full ~250k rows in memory at once.
func IngestEPSS(ctx context.Context, db *gorm.DB) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssFeedURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Encoding", "identity") // we handle gzip ourselves
	req.Header.Set("User-Agent", "spam-vuln-feeds/1.0")

	resp, err := epssClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("epss: status %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("epss: gunzip: %w", err)
	}
	defer gz.Close()

	rdr := csv.NewReader(gz)
	rdr.FieldsPerRecord = -1   // first non-comment line is the header
	rdr.Comment = '#'           // EPSS prefixes the model+date metadata with '#'

	// Peel the header so the loop below operates on data rows only.
	header, err := rdr.Read()
	if err != nil {
		return 0, fmt.Errorf("epss: read header: %w", err)
	}
	cveCol, scoreCol, pctCol := -1, -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "cve":
			cveCol = i
		case "epss":
			scoreCol = i
		case "percentile":
			pctCol = i
		}
	}
	if cveCol < 0 || scoreCol < 0 || pctCol < 0 {
		return 0, fmt.Errorf("epss: missing expected columns in header %v", header)
	}

	now := time.Now().UTC()
	scoreDate := now // model header is consumed by csv.Comment so we settle for ingest day

	const batchSize = 5000
	batch := make([]map[string]any, 0, batchSize)
	total := 0

	flush := func(tx *gorm.DB) error {
		if len(batch) == 0 {
			return nil
		}
		if err := tx.Table("epss_entries").CreateInBatches(batch, batchSize).Error; err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}

	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`TRUNCATE TABLE epss_entries`).Error; err != nil {
			return err
		}
		for {
			rec, err := rdr.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("epss: read row: %w", err)
			}
			if len(rec) <= cveCol || len(rec) <= scoreCol || len(rec) <= pctCol {
				continue
			}
			cve := strings.TrimSpace(rec[cveCol])
			if cve == "" {
				continue
			}
			score, err := strconv.ParseFloat(strings.TrimSpace(rec[scoreCol]), 32)
			if err != nil {
				continue
			}
			pct, err := strconv.ParseFloat(strings.TrimSpace(rec[pctCol]), 32)
			if err != nil {
				continue
			}
			batch = append(batch, map[string]any{
				"cve_id":     cve,
				"score":      float32(score),
				"percentile": float32(pct),
				"score_date": scoreDate,
				"fetched_at": now,
			})
			if len(batch) >= batchSize {
				if err := flush(tx); err != nil {
					return err
				}
			}
		}
		if err := flush(tx); err != nil {
			return err
		}
		if total == 0 {
			// Defensive: an empty payload (network glitch, upstream
			// outage) would otherwise commit a TRUNCATEd table and
			// erase our scoring data until the next daily run.
			// Roll back instead so the previous snapshot survives.
			return fmt.Errorf("epss: feed yielded 0 rows; aborting")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}
