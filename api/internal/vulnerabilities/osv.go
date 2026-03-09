package vulnerabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const osvURL = "https://api.osv.dev/v1/query"

// cacheTTL controls how long a cached result is considered fresh.
const cacheTTL = 24 * time.Hour

// osvRequest is the POST body for the OSV /v1/query endpoint.
type osvRequest struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Affected []affected `json:"affected"`
}

type affected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed,omitempty"`
}

// Result is a simplified vulnerability entry returned to callers.
type Result struct {
	VulnID   string `json:"vuln_id"`
	Summary  string `json:"summary"`
	FixedIn  string `json:"fixed_in,omitempty"`
	Source   string `json:"source"`
	// VEX override fields — populated when a ComponentVEX row exists.
	VEXStatus        string `json:"vex_status,omitempty"`
	VEXJustification string `json:"vex_justification,omitempty"`
	VEXDetail        string `json:"vex_detail,omitempty"`
}

// LookupPURL returns cached vulnerability results for a versioned PURL,
// refreshing from OSV when the cache is stale or missing.
func LookupPURL(ctx context.Context, db *gorm.DB, purl string) ([]Result, error) {
	// Check whether we have fresh cached data.
	var cached []ComponentVulnerability
	if err := db.WithContext(ctx).Where("purl = ?", purl).Find(&cached).Error; err != nil {
		return nil, fmt.Errorf("query cache: %w", err)
	}

	if len(cached) > 0 && time.Since(cached[0].CheckedAt) < cacheTTL {
		return applyVEX(ctx, db, purl, toResults(cached))
	}

	// Fetch from OSV.
	fresh, err := queryOSV(ctx, purl)
	if err != nil {
		// Return stale cache on error rather than failing.
		if len(cached) > 0 {
			return applyVEX(ctx, db, purl, toResults(cached))
		}
		return nil, fmt.Errorf("osv query: %w", err)
	}

	// Upsert results (including the "no vulns" case via delete+insert).
	now := time.Now().UTC()
	if err := db.WithContext(ctx).Where("purl = ?", purl).Delete(&ComponentVulnerability{}).Error; err != nil {
		return nil, fmt.Errorf("clear stale cache: %w", err)
	}
	if len(fresh) > 0 {
		rows := make([]ComponentVulnerability, len(fresh))
		for i, v := range fresh {
			rows[i] = ComponentVulnerability{
				PURL:      purl,
				VulnID:    v.VulnID,
				Summary:   v.Summary,
				FixedIn:   v.FixedIn,
				Source:    "osv",
				CheckedAt: now,
			}
		}
		if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error; err != nil {
			return nil, fmt.Errorf("cache vulns: %w", err)
		}
	} else {
		// Insert a sentinel row so we know we checked and found nothing.
		sentinel := ComponentVulnerability{
			PURL:      purl,
			VulnID:    "_none",
			Source:    "osv",
			CheckedAt: now,
		}
		db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&sentinel)
	}

	return applyVEX(ctx, db, purl, fresh)
}

// SetVEX upserts a VEX override for a PURL+vulnID pair.
func SetVEX(ctx context.Context, db *gorm.DB, purl, vulnID, status, justification, detail string) error {
	vex := ComponentVEX{
		PURL:          purl,
		VulnID:        vulnID,
		Status:        status,
		Justification: justification,
		Detail:        detail,
		CreatedAt:     time.Now().UTC(),
	}
	return db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "purl"}, {Name: "vuln_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"status", "justification", "detail", "created_at"}),
		}).
		Create(&vex).Error
}

func queryOSV(ctx context.Context, purl string) ([]Result, error) {
	body := osvRequest{}
	body.Package.PURL = purl

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(osvResp.Vulns))
	for _, v := range osvResp.Vulns {
		r := Result{VulnID: v.ID, Summary: v.Summary, Source: "osv"}
		r.FixedIn = extractFixedIn(v.Affected)
		results = append(results, r)
	}
	return results, nil
}

func extractFixedIn(affected []affected) string {
	for _, a := range affected {
		for _, rng := range a.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

func toResults(rows []ComponentVulnerability) []Result {
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		if r.VulnID == "_none" {
			continue
		}
		out = append(out, Result{
			VulnID:  r.VulnID,
			Summary: r.Summary,
			FixedIn: r.FixedIn,
			Source:  r.Source,
		})
	}
	return out
}

func applyVEX(ctx context.Context, db *gorm.DB, purl string, results []Result) ([]Result, error) {
	if len(results) == 0 {
		return results, nil
	}

	var vexRows []ComponentVEX
	if err := db.WithContext(ctx).Where("purl = ?", purl).Find(&vexRows).Error; err != nil {
		return results, nil // non-fatal
	}

	vexMap := make(map[string]ComponentVEX, len(vexRows))
	for _, v := range vexRows {
		vexMap[v.VulnID] = v
	}

	for i, r := range results {
		if v, ok := vexMap[r.VulnID]; ok {
			results[i].VEXStatus = v.Status
			results[i].VEXJustification = v.Justification
			results[i].VEXDetail = v.Detail
		}
	}
	return results, nil
}
