package vulnmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

// kevFeedURL is CISA's public Known Exploited Vulnerabilities catalog —
// JSON, no auth, ~1.5k entries today. Refreshed by CISA whenever a new
// exploited vulnerability is added (typically every few days).
const kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

var kevClient = &http.Client{Timeout: 60 * time.Second}

// kevCatalog is the CISA feed envelope. Title / catalogVersion /
// dateReleased are surfaced in the import log so operators can verify
// freshness of the ingest.
type kevCatalog struct {
	Title          string             `json:"title"`
	CatalogVersion string             `json:"catalogVersion"`
	DateReleased  string              `json:"dateReleased"`
	Count          int                `json:"count"`
	Vulnerabilities []kevVulnerability `json:"vulnerabilities"`
}

// kevVulnerability is one row in the catalog. KnownRansomwareCampaignUse
// is "Known" / "Unknown" / "" in the feed; we coerce to a boolean
// since downstream consumers care about the binary signal.
type kevVulnerability struct {
	CveID                       string `json:"cveID"`
	VendorProject               string `json:"vendorProject"`
	Product                     string `json:"product"`
	VulnerabilityName           string `json:"vulnerabilityName"`
	DateAdded                   string `json:"dateAdded"`
	ShortDescription            string `json:"shortDescription"`
	RequiredAction              string `json:"requiredAction"`
	DueDate                     string `json:"dueDate"`
	KnownRansomwareCampaignUse  string `json:"knownRansomwareCampaignUse"`
	Notes                       string `json:"notes"`
}

// IngestKEV fetches the latest CISA KEV catalog and replaces the
// cisa_kev_entries table contents inside a transaction. Truncate +
// bulk insert is the simplest correct semantics: any CVE no longer in
// the feed (rare — CISA appends, rarely removes) drops out, and we
// don't accumulate cruft. Returns the row count actually inserted so
// the job result records visible progress.
func IngestKEV(ctx context.Context, db *gorm.DB) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spam-vuln-feeds/1.0")

	resp, err := kevClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("kev: status %d", resp.StatusCode)
	}

	// Catalog is ~1 MB; cap higher just in case CISA grows it.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, err
	}
	var cat kevCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return 0, fmt.Errorf("kev: decode: %w", err)
	}
	if len(cat.Vulnerabilities) == 0 {
		// Empty payload would wipe the table — refuse so a
		// transient feed glitch can't drop our exploitation
		// signal entirely. The next run will retry.
		return 0, fmt.Errorf("kev: feed returned 0 entries; refusing to truncate")
	}

	rows := make([]map[string]any, 0, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		cve := strings.TrimSpace(v.CveID)
		if cve == "" {
			continue
		}
		rows = append(rows, map[string]any{
			"cve_id":            cve,
			"vendor_project":    v.VendorProject,
			"product":           v.Product,
			"vuln_name":         v.VulnerabilityName,
			"short_description": v.ShortDescription,
			"required_action":   v.RequiredAction,
			"date_added":        nullableDate(v.DateAdded),
			"due_date":          nullableDate(v.DueDate),
			"known_ransomware":  strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known"),
			"notes":             v.Notes,
			"fetched_at":        time.Now().UTC(),
		})
	}

	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`TRUNCATE TABLE cisa_kev_entries`).Error; err != nil {
			return err
		}
		// Bulk insert in chunks — GORM's CreateInBatches keeps the
		// statement size well under Postgres' parameter limit.
		return tx.Table("cisa_kev_entries").CreateInBatches(rows, 500).Error
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// nullableDate returns *time.Time for ISO YYYY-MM-DD inputs and nil
// otherwise — KEV occasionally has empty due_date strings.
func nullableDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}
