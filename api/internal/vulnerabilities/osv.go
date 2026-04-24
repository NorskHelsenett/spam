package vulnerabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/vulnmeta"
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
	ID               string              `json:"id"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details"`
	Affected         []affected          `json:"affected"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type affected struct {
	Ranges            []osvRange        `json:"ranges"`
	EcosystemSpecific ecosystemSpecific `json:"ecosystem_specific"`
}

type ecosystemSpecific struct {
	Severity string `json:"severity"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Result is a simplified vulnerability entry returned to callers.
type Result struct {
	VulnID      string `json:"vuln_id"`
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
	Source      string `json:"source"`
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
				PURL:        purl,
				VulnID:      v.VulnID,
				Summary:     v.Summary,
				Description: v.Description,
				Severity:    v.Severity,
				FixedIn:     v.FixedIn,
				Source:      "osv",
				CheckedAt:   now,
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

// SetVEX upserts a VEX override for a PURL+vulnID pair. When the
// given vulnID is an alias of a known advisory, the row is stored
// under the canonical id so future scanner reports under any alias
// find the suppression via the same canonical route used by
// applyVEX's lookup. Unknown ids (no enrichment yet) store verbatim
// — re-enrichment later doesn't retroactively migrate these rows,
// so long-lived installations may accumulate some alias-keyed rows
// that applyVEX still honours via its expansion logic.
func SetVEX(ctx context.Context, db *gorm.DB, purl, vulnID, status, justification, detail string) error {
	canonical := vulnmeta.ResolveCanonical(ctx, db, vulnID)
	vex := ComponentVEX{
		PURL:          purl,
		VulnID:        canonical,
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

	installed := purlVersion(purl)
	results := make([]Result, 0, len(osvResp.Vulns))
	for _, v := range osvResp.Vulns {
		r := Result{VulnID: v.ID, Summary: v.Summary, Description: v.Details, Source: "osv"}
		r.FixedIn = pickApplicableFix(v.Affected, installed)
		r.Severity = extractSeverity(v)
		results = append(results, r)
	}
	return results, nil
}

// purlVersion extracts the @version component from a PURL string.
// Returns "" when the PURL has no version or the format can't be
// parsed — callers fall back to the first-range fix in that case.
//
// PURL grammar: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
// We want the substring after the last @ and before ? / # / end.
func purlVersion(purl string) string {
	at := strings.LastIndex(purl, "@")
	if at == -1 {
		return ""
	}
	v := purl[at+1:]
	for _, sep := range []byte{'?', '#'} {
		if i := strings.IndexByte(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

// pickApplicableFix returns the fix version for the range containing
// the installed version. When installed is unknown we fall back to
// the first-range fix (extractFixedIn's pre-existing behaviour), so
// callers without version context aren't worse off than before.
//
// Mirrors vulnmeta.ApplicableFix but operates on this package's
// osv.go type shape. Uses the exported version comparator from
// vulnmeta so both call sites agree on how to compare versions.
func pickApplicableFix(affected []affected, installed string) string {
	if installed == "" {
		return extractFixedIn(affected)
	}
	for _, a := range affected {
		for _, rng := range a.Ranges {
			var introduced string
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					introduced = ev.Introduced
					continue
				}
				if ev.Fixed != "" {
					if vulnmeta.InInterval(installed, introduced, ev.Fixed) {
						return ev.Fixed
					}
					introduced = ""
				}
			}
		}
	}
	// No matching interval — return the first fix so the UI still
	// surfaces *a* patched version. May be wrong for this installed
	// version, but the scanner's behaviour without this helper was
	// the same.
	return extractFixedIn(affected)
}

// FetchVulnDetails fetches full vulnerability details from OSV for a single vuln ID.
func FetchVulnDetails(ctx context.Context, vulnID string) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.osv.dev/v1/vulns/"+vulnID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vulns/%s returned %d", vulnID, resp.StatusCode)
	}
	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
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

// extractSeverity picks severity from database_specific first, then ecosystem_specific.
// MODERATE (used by GHSA) is normalised to MEDIUM.
func extractSeverity(v osvVuln) string {
	s := strings.ToUpper(v.DatabaseSpecific.Severity)
	if s == "" {
		for _, a := range v.Affected {
			if s = strings.ToUpper(a.EcosystemSpecific.Severity); s != "" {
				break
			}
		}
	}
	if s == "MODERATE" {
		return "MEDIUM"
	}
	return s
}

func toResults(rows []ComponentVulnerability) []Result {
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		if r.VulnID == "_none" {
			continue
		}
		out = append(out, Result{
			VulnID:      r.VulnID,
			Summary:     r.Summary,
			Description: r.Description,
			Severity:    r.Severity,
			FixedIn:     r.FixedIn,
			Source:      r.Source,
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
	if len(vexRows) == 0 {
		return results, nil
	}

	// Route both sides through canonical ids so a VEX keyed under any
	// alias (legacy rows predating the SetVEX normalization, or VEX
	// set before enrichment landed) still matches scanner findings
	// reported under a different alias of the same advisory.
	idSet := make(map[string]struct{}, len(vexRows)+len(results))
	for _, v := range vexRows {
		idSet[v.VulnID] = struct{}{}
	}
	for _, r := range results {
		idSet[r.VulnID] = struct{}{}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	canonicals, _ := vulnmeta.ResolveCanonicals(ctx, db, ids)

	vexMap := make(map[string]ComponentVEX, len(vexRows))
	for _, v := range vexRows {
		vexMap[canonicals[v.VulnID]] = v
	}

	for i, r := range results {
		if v, ok := vexMap[canonicals[r.VulnID]]; ok {
			results[i].VEXStatus = v.Status
			results[i].VEXJustification = v.Justification
			results[i].VEXDetail = v.Detail
		}
	}
	return results, nil
}
