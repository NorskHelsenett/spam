package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

type AdvancedSearchResult struct {
	Type       string `json:"type"`
	SourceRef  string `json:"source_ref,omitempty"`
	RepoID     string `json:"repo_id"`
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	OwnerPath  string `json:"owner_path,omitempty"`
	Org        string `json:"org"`
	Slug       string `json:"slug"`
	Title      string `json:"title"`
	Value      string `json:"value,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

type AdvancedSearchResponse struct {
	Query   string                 `json:"query"`
	Target  string                 `json:"target"`
	Results []AdvancedSearchResult `json:"results"`
	HasMore bool                   `json:"has_more"`
}

const osvVulnDetailsURL = "https://api.osv.dev/v1/vulns/"

type osvVulnDetail struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			PURL string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func collectFixedVersions(detail *osvVulnDetail) string {
	if detail == nil {
		return ""
	}

	seen := make(map[string]struct{})
	versions := make([]string, 0)
	for _, affected := range detail.Affected {
		for _, rng := range affected.Ranges {
			for _, event := range rng.Events {
				fixed := strings.TrimSpace(event.Fixed)
				if fixed == "" {
					continue
				}
				if _, ok := seen[fixed]; ok {
					continue
				}
				seen[fixed] = struct{}{}
				versions = append(versions, fixed)
			}
		}
	}
	return strings.Join(versions, ", ")
}

func criticalityFromSeverity(detail *osvVulnDetail) string {
	if detail == nil {
		return ""
	}

	maxRank := 0
	for _, s := range detail.Severity {
		score := strings.TrimSpace(s.Score)
		if score == "" {
			continue
		}
		if rank := severityRank(score); rank > maxRank {
			maxRank = rank
		}
	}
	if maxRank > 0 {
		return criticalityFromRank(maxRank)
	}
	return ""
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func criticalityFromRank(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return ""
	}
}

func criticalityFromSeverityString(value string) string {
	maxRank := 0
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == '/' }) {
		if rank := severityRank(part); rank > maxRank {
			maxRank = rank
		}
	}
	return criticalityFromRank(maxRank)
}

func fetchVulnerabilityDetails(ctx context.Context, vulnID string) (*osvVulnDetail, error) {
	if strings.TrimSpace(vulnID) == "" {
		return nil, nil
	}

	escaped := url.PathEscape(vulnID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnDetailsURL+escaped, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV details request failed with status %d", resp.StatusCode)
	}

	var detail osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}

	if detail.ID == "" {
		detail.ID = vulnID
	}
	return &detail, nil
}

func appendVulnMetadata(metadata map[string]string, detail *osvVulnDetail, fallbackSummary string, fixedIn string) {
	if detail == nil {
		return
	}

	if strings.TrimSpace(fixedIn) == "" {
		fixedIn = collectFixedVersions(detail)
	}

	metadata["vuln_id_osv"] = detail.ID
	if strings.TrimSpace(detail.Summary) != "" {
		metadata["summary"] = detail.Summary
	} else if strings.TrimSpace(fallbackSummary) != "" {
		metadata["summary"] = fallbackSummary
	}
	if strings.TrimSpace(detail.Details) != "" {
		metadata["details"] = strings.TrimSpace(detail.Details)
	}
	if strings.TrimSpace(fixedIn) != "" {
		metadata["fixed_in"] = fixedIn
	}
	if len(detail.Aliases) > 0 {
		metadata["aliases"] = strings.Join(detail.Aliases, ", ")
	}
	if len(detail.References) > 0 {
		refs := make([]string, 0, len(detail.References))
		for _, ref := range detail.References {
			refType := strings.TrimSpace(ref.Type)
			refURL := strings.TrimSpace(ref.URL)
			if refURL == "" {
				continue
			}
			if refType != "" {
				refs = append(refs, refType+": "+refURL)
			} else {
				refs = append(refs, refURL)
			}
		}
		if len(refs) > 0 {
			metadata["references"] = strings.Join(refs, "\n")
		}
	}
	if len(detail.Severity) > 0 {
		levels := make([]string, 0, len(detail.Severity))
		for _, s := range detail.Severity {
			if strings.TrimSpace(s.Type) == "" || strings.TrimSpace(s.Score) == "" {
				continue
			}
			levels = append(levels, s.Type+": "+s.Score)
		}
		if len(levels) > 0 {
			metadata["severity"] = strings.Join(levels, ", ")
		}
	}
	if criticality := criticalityFromSeverity(detail); criticality != "" {
		metadata["criticality"] = criticality
	}
}

func resolveVulnIDCandidates(ctx context.Context, db *gorm.DB, vulnID string) []string {
	vulnID = strings.TrimSpace(vulnID)
	if vulnID == "" {
		return nil
	}

	lower := strings.ToLower(vulnID)
	if !strings.HasPrefix(lower, "cve-") && !strings.HasPrefix(lower, "ghsa-") && !strings.HasPrefix(lower, "go-") {
		return []string{vulnID}
	}

	ids := make([]string, 0, 4)
	seen := map[string]struct{}{}
	addID := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		ids = append(ids, id)
	}

	addID(vulnID)

	if db != nil {
		like := "%" + vulnID + "%"
		type vulnRow struct {
			VulnID string `gorm:"column:vuln_id"`
		}
		dbCandidates := make([]vulnRow, 0, 5)
		if err := db.WithContext(ctx).Raw(`
			SELECT DISTINCT vuln_id
			FROM component_vulnerabilities
			WHERE vuln_id ILIKE ? OR vuln_id <% ?
			   OR summary ILIKE ? OR source ILIKE ? OR fixed_in ILIKE ?
			   OR aliases ILIKE ? OR details ILIKE ? OR references ILIKE ?
		`, like, vulnID, like, like, like, like, like, like).Scan(&dbCandidates).Error; err == nil {
			for _, row := range dbCandidates {
				addID(row.VulnID)
			}
		} else {
			if err := db.WithContext(ctx).Raw(`
				SELECT DISTINCT vuln_id
				FROM component_vulnerabilities
				WHERE vuln_id ILIKE ? OR summary ILIKE ? OR source ILIKE ? OR fixed_in ILIKE ?
				  OR aliases ILIKE ? OR details ILIKE ? OR references ILIKE ?
			`, like, like, like, like, like, like, like).Scan(&dbCandidates).Error; err == nil {
				for _, row := range dbCandidates {
					addID(row.VulnID)
				}
			}
		}
		if len(ids) > 1 {
			return ids
		}
	}

	detail, err := fetchVulnerabilityDetails(ctx, vulnID)
	if err != nil || detail == nil {
		return ids
	}
	addID(detail.ID)
	for _, alias := range detail.Aliases {
		addID(alias)
	}
	return ids
}

func buildLikeClause(column string) string {
	return "(" + column + " ILIKE ?)"
}

func buildMultiValueLikeClause(column string, values []string, fallback string) (string, []interface{}) {
	effective := values
	if len(effective) == 0 {
		effective = []string{fallback}
	}

	parts := make([]string, 0, len(effective))
	args := make([]interface{}, 0, len(effective))
	for _, value := range effective {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parts = append(parts, buildLikeClause(column))
		args = append(args, "%"+value+"%")
	}
	if len(parts) == 0 {
		fallbackLike := "%" + strings.TrimSpace(fallback) + "%"
		parts = append(parts, buildLikeClause(column))
		args = append(args, fallbackLike)
	}

	return "(" + strings.Join(parts, " OR ") + ")", args
}

type advancedSearchDBRow struct {
	Type       string
	SourceRef  string
	RepoID     string
	Provider   string
	ProviderID string
	BaseURL    string
	OwnerPath  string
	Org        string
	Slug       string
	Title      string
	Value      string
	SourceText string
	CreatedAt  time.Time
}

var advancedSearchTargets = map[string]struct{}{
	"manifest":    {},
	"sbom":        {},
	"secret":      {},
	"contributor": {},
	"language":    {},
	"commit":      {},
	"repo":        {},
	"readme":      {},
	"vuln":        {},
	"vex":         {},
}

func normalizeAdvancedTargets(target string) []string {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" || target == "all" {
		return []string{"repo", "commit", "language", "contributor", "readme", "manifest", "sbom", "secret", "vuln", "vex"}
	}
	parts := strings.Split(target, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, raw := range parts {
		t := strings.TrimSpace(strings.ToLower(raw))
		if t == "" {
			continue
		}
		if _, ok := advancedSearchTargets[t]; !ok {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return []string{"repo", "commit", "language", "contributor", "readme", "manifest", "sbom", "secret", "vuln", "vex"}
	}
	return out
}

func compactSnippet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

func snippetAround(source, query string) string {
	src := strings.TrimSpace(source)
	q := strings.TrimSpace(query)
	if src == "" {
		return ""
	}
	if q == "" {
		return compactSnippet(src)
	}
	lowerSrc := strings.ToLower(src)
	lowerQ := strings.ToLower(q)
	pos := strings.Index(lowerSrc, lowerQ)
	if pos < 0 {
		return ""
	}
	start := pos - 90
	if start < 0 {
		start = 0
	}
	end := pos + len(q) + 130
	if end > len(src) {
		end = len(src)
	}
	snippet := src[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(src) {
		snippet += "..."
	}
	return compactSnippet(snippet)
}

func runAdvancedSearchQuery(db *gorm.DB, r *http.Request, query string, perTargetLimit int, target string) ([]advancedSearchDBRow, error) {
	like := "%" + query + "%"
	var rows []advancedSearchDBRow

	switch target {
	case "manifest":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'manifest' AS type,
				m.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
				r.slug,
				COALESCE(m.path, m.type, '') AS title,
				COALESCE(m.type, '') AS value,
				CASE
					WHEN strpos(lower(hs.haystack), lower(?)) > 0 THEN
						(CASE WHEN strpos(lower(hs.haystack), lower(?)) > 90 THEN '...' ELSE '' END) ||
						substr(hs.haystack, GREATEST(1, strpos(lower(hs.haystack), lower(?)) - 90), length(?) + 220) ||
						(CASE WHEN strpos(lower(hs.haystack), lower(?)) + length(?) + 130 < length(hs.haystack) THEN '...' ELSE '' END)
					ELSE LEFT(hs.haystack, 240)
				END AS source_text,
				m.created_at
			FROM manifests m
			JOIN repos r ON r.id = m.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			CROSS JOIN LATERAL (
				SELECT COALESCE(m.path, '') || E'\n' || COALESCE(m.type, '') || E'\n' || COALESCE(m.content, '') AS haystack
			) hs
			WHERE m.path ILIKE ? OR m.type ILIKE ? OR m.content ILIKE ?
			ORDER BY m.created_at DESC
			LIMIT ?
		`, query, query, query, query, query, query, like, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "sbom":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'sbom' AS type,
				s.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					s.format AS title,
					rc.commit_sha AS value,
					LEFT(COALESCE(s.format, '') || E'\n' || COALESCE(convert_from(s.content_bytes, 'utf8'), ''), 60000) AS source_text,
					s.created_at
			FROM sboms s
			JOIN sbom_bindings sb ON sb.sbom_id = s.id AND sb.asset_type = 'REPO_COMMIT'
			JOIN repo_commits rc ON rc.id = sb.asset_ref_id
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE s.format ILIKE ? OR convert_from(s.content_bytes, 'utf8') ILIKE ?
			ORDER BY s.created_at DESC
			LIMIT ?
		`, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "secret":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'secret' AS type,
				rs.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Secret findings' AS title,
					COALESCE(rs.run_id, '') AS value,
					LEFT(COALESCE(rs.findings::text, ''), 60000) AS source_text,
					rs.created_at
			FROM run_secrets rs
			JOIN repos r ON r.id = rs.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rs.findings::text ILIKE ?
			ORDER BY rs.created_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "vex":
		vexVulnIDCandidates := resolveVulnIDCandidates(r.Context(), db, query)
		vexVulnIDClause, vexVulnIDArgs := buildMultiValueLikeClause("cv.vuln_id", vexVulnIDCandidates, query)
		vexStatusClause, vexStatusArgs := buildMultiValueLikeClause("cv.status", vexVulnIDCandidates, query)
		vexJustificationClause, vexJustificationArgs := buildMultiValueLikeClause("cv.justification", vexVulnIDCandidates, query)
		vexDetailClause, vexDetailArgs := buildMultiValueLikeClause("cv.detail", vexVulnIDCandidates, query)
		vexArgs := make([]interface{}, 0, 1+len(vexVulnIDArgs)+len(vexStatusArgs)+len(vexJustificationArgs)+len(vexDetailArgs)+1)
		vexArgs = append(vexArgs, like)
		vexArgs = append(vexArgs, vexVulnIDArgs...)
		vexArgs = append(vexArgs, vexStatusArgs...)
		vexArgs = append(vexArgs, vexJustificationArgs...)
		vexArgs = append(vexArgs, vexDetailArgs...)
		vexArgs = append(vexArgs, perTargetLimit)
		var hasTable bool
		if err := db.WithContext(r.Context()).Raw("SELECT to_regclass('public.component_vex') IS NOT NULL").Scan(&hasTable).Error; err != nil {
			return nil, err
		}
		if !hasTable {
			return []advancedSearchDBRow{}, nil
		}
		err := db.WithContext(r.Context()).Raw(fmt.Sprintf(`
				WITH vuln_repos AS (
				SELECT DISTINCT
					s.purl AS p_url,
					r.id AS repo_id,
					r.provider,
					COALESCE(pi.id, '') AS provider_id,
					COALESCE(pi.base_url, '') AS base_url,
					COALESCE(pi.owner_path, '') AS owner_path,
					r.org,
					r.slug
				FROM sbom_component_view s
				JOIN repo_commits rc ON rc.id = s.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
				WHERE s.purl IS NOT NULL
				  AND s.asset_type = 'REPO_COMMIT'
				  AND s.is_root = false
			)
				SELECT
					'vex' AS type,
				cv.p_url AS source_ref,
				vr.repo_id,
				vr.provider,
				vr.provider_id,
				vr.base_url,
				vr.owner_path,
				vr.org,
				vr.slug,
				'VEX override' AS title,
				cv.vuln_id AS value,
				LEFT(
					CONCAT_WS(
						E'\n',
						COALESCE(cv.p_url, ''),
						COALESCE(cv.vuln_id, ''),
						COALESCE(cv.status, ''),
						COALESCE(cv.justification, ''),
						COALESCE(cv.detail, '')
					),
					60000
				) AS source_text,
				CURRENT_TIMESTAMP AS created_at
				FROM component_vex cv
				JOIN vuln_repos vr ON vr.p_url = cv.p_url
				WHERE cv.p_url ILIKE ?
					OR (%s)
					OR %s
					OR %s
					OR %s
				ORDER BY cv.vuln_id, cv.p_url, vr.org, vr.slug
				LIMIT ?
				`, vexVulnIDClause, vexStatusClause, vexJustificationClause, vexDetailClause), vexArgs...).Scan(&rows).Error
		return rows, err
	case "vuln":
		vulnIDCandidates := resolveVulnIDCandidates(r.Context(), db, query)
		vulnIDClause, vulnIDArgs := buildMultiValueLikeClause("cv.vuln_id", vulnIDCandidates, query)
		vulnSeverityClause, vulnSeverityArgs := buildMultiValueLikeClause("cv.severity", vulnIDCandidates, query)
		vulnSummaryClause, vulnSummaryArgs := buildMultiValueLikeClause("cv.summary", vulnIDCandidates, query)
		vulnFixedClause, vulnFixedArgs := buildMultiValueLikeClause("cv.fixed_in", vulnIDCandidates, query)
		vulnSourceClause, vulnSourceArgs := buildMultiValueLikeClause("cv.source", vulnIDCandidates, query)
		vulnAliasesClause, vulnAliasesArgs := buildMultiValueLikeClause("cv.aliases", vulnIDCandidates, query)
		vulnDetailsClause, vulnDetailsArgs := buildMultiValueLikeClause("cv.details", vulnIDCandidates, query)
		vulnReferencesClause, vulnReferencesArgs := buildMultiValueLikeClause("cv.references", vulnIDCandidates, query)
		vulnArgs := make([]interface{}, 0, 1+len(vulnIDArgs)+len(vulnSeverityArgs)+len(vulnSummaryArgs)+len(vulnFixedArgs)+len(vulnSourceArgs)+len(vulnAliasesArgs)+len(vulnDetailsArgs)+len(vulnReferencesArgs)+1)
		vulnArgs = append(vulnArgs, like)
		vulnArgs = append(vulnArgs, vulnIDArgs...)
		vulnArgs = append(vulnArgs, vulnSeverityArgs...)
		vulnArgs = append(vulnArgs, vulnSummaryArgs...)
		vulnArgs = append(vulnArgs, vulnFixedArgs...)
		vulnArgs = append(vulnArgs, vulnSourceArgs...)
		vulnArgs = append(vulnArgs, vulnAliasesArgs...)
		vulnArgs = append(vulnArgs, vulnDetailsArgs...)
		vulnArgs = append(vulnArgs, vulnReferencesArgs...)
		vulnArgs = append(vulnArgs, perTargetLimit)
		var hasTable bool
		if err := db.WithContext(r.Context()).Raw("SELECT to_regclass('public.component_vulnerabilities') IS NOT NULL").Scan(&hasTable).Error; err != nil {
			return nil, err
		}
		if !hasTable {
			return []advancedSearchDBRow{}, nil
		}
		err := db.WithContext(r.Context()).Raw(fmt.Sprintf(`
				WITH vuln_repos AS (
				SELECT DISTINCT
					s.purl AS p_url,
					r.id AS repo_id,
					r.provider,
					COALESCE(pi.id, '') AS provider_id,
					COALESCE(pi.base_url, '') AS base_url,
					COALESCE(pi.owner_path, '') AS owner_path,
					r.org,
					r.slug
				FROM sbom_component_view s
				JOIN repo_commits rc ON rc.id = s.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
				WHERE s.purl IS NOT NULL
				  AND s.asset_type = 'REPO_COMMIT'
				  AND s.is_root = false
			)
			SELECT
				'vuln' AS type,
				cv.p_url AS source_ref,
				vr.repo_id,
				vr.provider,
				vr.provider_id,
				vr.base_url,
				vr.owner_path,
				vr.org,
				vr.slug,
				'Vulnerability' AS title,
				cv.vuln_id AS value,
					LEFT(
						CONCAT_WS(
							E'\n',
							COALESCE(cv.p_url, ''),
							COALESCE(cv.vuln_id, ''),
							COALESCE(cv.severity, ''),
							COALESCE(cv.summary, ''),
							COALESCE(cv.fixed_in, ''),
							COALESCE(cv.source, ''),
							COALESCE(cv.aliases, ''),
							COALESCE(cv.details, ''),
							COALESCE(cv.references, '')
						),
						60000
					) AS source_text,
					CURRENT_TIMESTAMP AS created_at
				FROM component_vulnerabilities cv
				JOIN vuln_repos vr ON vr.p_url = cv.p_url
					WHERE cv.p_url ILIKE ?
						OR (%s)
						OR %s
						OR %s
						OR %s
						OR %s
						OR %s
						OR %s
						OR %s
					ORDER BY cv.vuln_id, cv.p_url, vr.org, vr.slug
					LIMIT ?
					`, vulnIDClause, vulnSeverityClause, vulnSummaryClause, vulnFixedClause, vulnSourceClause, vulnAliasesClause, vulnDetailsClause, vulnReferencesClause), vulnArgs...).Scan(&rows).Error
		return rows, err
	case "contributor":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'contributor' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Contributors' AS title,
					'' AS value,
					LEFT(COALESCE(rc.contributors_json, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.contributors_json ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "language":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'language' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Languages' AS title,
					'' AS value,
					LEFT(COALESCE(rc.details_json, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.details_json ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "commit":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'commit' AS type,
				c.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Commit' AS title,
					c.commit_sha AS value,
					LEFT(COALESCE(c.commit_sha, '') || E'\n' || COALESCE(c.ref, ''), 60000) AS source_text,
					c.created_at
			FROM repo_commits c
			JOIN repos r ON r.id = c.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE c.commit_sha ILIKE ? OR c.ref ILIKE ?
			ORDER BY c.created_at DESC
			LIMIT ?
		`, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "repo":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'repo' AS type,
				r.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					r.org || '/' || r.slug AS title,
					r.provider AS value,
					LEFT((r.org || '/' || r.slug || E'\n' || COALESCE(r.provider, '')), 60000) AS source_text,
					r.created_at
			FROM repos r
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE r.org ILIKE ? OR r.slug ILIKE ? OR (r.org || '/' || r.slug) ILIKE ?
			ORDER BY r.created_at DESC
			LIMIT ?
		`, like, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "readme":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'readme' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'README' AS title,
					'' AS value,
					LEFT(COALESCE(rc.readme_content, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.readme_content ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	default:
		return []advancedSearchDBRow{}, nil
	}
}

// AdvancedSearchHandler runs cross-domain searches over repo metadata and artifacts.
// GET /api/search/advanced?q=<query>&target=<all|repo|commit|language|contributor|readme|manifest|sbom|secret|vuln|vex>
func AdvancedSearchHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		target := strings.TrimSpace(r.URL.Query().Get("target"))

		perPage := 100
		if p, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && p > 0 && p <= 300 {
			perPage = p
		}

		if q == "" {
			writeJSON(w, http.StatusOK, AdvancedSearchResponse{Query: q, Target: target, Results: []AdvancedSearchResult{}, HasMore: false})
			return
		}

		targets := normalizeAdvancedTargets(target)
		perTargetLimit := perPage
		if perTargetLimit < 20 {
			perTargetLimit = 20
		}

		results := make([]AdvancedSearchResult, 0, perPage)
		seen := map[string]struct{}{}

		for _, t := range targets {
			rows, err := runAdvancedSearchQuery(db, r, q, perTargetLimit, t)
			if err != nil {
				http.Error(w, "search failed", http.StatusInternalServerError)
				return
			}
			for _, row := range rows {
				key := row.Type + "|" + row.RepoID + "|" + row.Title + "|" + row.Value + "|" + row.SourceRef
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				snippet := snippetAround(row.SourceText, q)
				if snippet == "" {
					snippet = snippetAround(row.Title+" "+row.Value, q)
				}
				results = append(results, AdvancedSearchResult{
					Type:       row.Type,
					SourceRef:  row.SourceRef,
					RepoID:     row.RepoID,
					Provider:   row.Provider,
					ProviderID: row.ProviderID,
					BaseURL:    row.BaseURL,
					OwnerPath:  row.OwnerPath,
					Org:        row.Org,
					Slug:       row.Slug,
					Title:      row.Title,
					Value:      row.Value,
					Snippet:    snippet,
					CreatedAt:  row.CreatedAt.UTC().Format(time.RFC3339),
				})
			}
		}

		hasMore := len(results) > perPage
		if hasMore {
			results = results[:perPage]
		}

		writeJSON(w, http.StatusOK, AdvancedSearchResponse{
			Query:   q,
			Target:  target,
			Results: results,
			HasMore: hasMore,
		})
	}
}

type AdvancedSearchPreviewResponse struct {
	Type      string            `json:"type"`
	Raw       string            `json:"raw"`
	Metadata  map[string]string `json:"metadata"`
	RepoID    string            `json:"repo_id,omitempty"`
	Provider  string            `json:"provider,omitempty"`
	Org       string            `json:"org,omitempty"`
	Slug      string            `json:"slug,omitempty"`
	SourceRef string            `json:"source_ref,omitempty"`
}

// AdvancedSearchPreviewHandler returns raw source content plus metadata for a search hit.
// GET /api/search/preview?type=<type>&source_ref=<id>&repo_id=<repo_id>
func AdvancedSearchPreviewHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		targetType := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("type")))
		sourceRef := strings.TrimSpace(r.URL.Query().Get("source_ref"))
		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))

		if targetType == "" || sourceRef == "" {
			http.Error(w, "type and source_ref required", http.StatusBadRequest)
			return
		}
		if _, ok := advancedSearchTargets[targetType]; !ok {
			http.Error(w, "unsupported type", http.StatusBadRequest)
			return
		}

		resp := AdvancedSearchPreviewResponse{
			Type:      targetType,
			SourceRef: sourceRef,
			Metadata:  map[string]string{},
		}

		switch targetType {
		case "manifest":
			var row struct {
				ID       string
				RepoID   string
				Path     string
				Type     string
				Content  string
				Metadata string
				Provider string
				Org      string
				Slug     string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					m.id,
					m.repo_id,
					m.path,
					m.type,
					COALESCE(m.content, '') AS content,
					COALESCE(m.metadata::text, '{}') AS metadata,
					r.provider,
					r.org,
					r.slug
				FROM manifests m
				JOIN repos r ON r.id = m.repo_id
				WHERE m.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Content
			resp.Metadata["path"] = row.Path
			resp.Metadata["manifest_type"] = row.Type
			resp.Metadata["manifest_id"] = row.ID
			resp.Metadata["manifest_metadata_json"] = row.Metadata
		case "sbom":
			var row struct {
				ID        string
				Format    string
				Raw       string
				RepoID    string
				Provider  string
				Org       string
				Slug      string
				CommitSHA string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					s.id,
					s.format,
					COALESCE(convert_from(s.content_bytes, 'utf8'), '') AS raw,
					r.id AS repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.commit_sha, '') AS commit_sha
				FROM sboms s
				JOIN sbom_bindings sb ON sb.sbom_id = s.id AND sb.asset_type = 'REPO_COMMIT'
				JOIN repo_commits rc ON rc.id = sb.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				WHERE s.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["sbom_id"] = row.ID
			resp.Metadata["format"] = row.Format
			if row.CommitSHA != "" {
				resp.Metadata["commit_sha"] = row.CommitSHA
			}
		case "secret":
			var row struct {
				ID           string
				RepoID       string
				Provider     string
				Org          string
				Slug         string
				RunID        string
				FindingCount int
				Raw          string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					rs.id,
					rs.repo_id,
					r.provider,
					r.org,
					r.slug,
					rs.run_id,
					rs.finding_count,
					COALESCE(rs.findings::text, '') AS raw
				FROM run_secrets rs
				JOIN repos r ON r.id = rs.repo_id
				WHERE rs.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["run_id"] = row.RunID
			resp.Metadata["finding_count"] = strconv.Itoa(row.FindingCount)
			resp.Metadata["secret_id"] = row.ID
		case "contributor", "language", "readme":
			var row struct {
				RepoID           string
				Provider         string
				Org              string
				Slug             string
				ReadmeContent    string
				ContributorsJSON string
				DetailsJSON      string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					rc.repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.readme_content, '') AS readme_content,
					COALESCE(rc.contributors_json, '') AS contributors_json,
					COALESCE(rc.details_json, '') AS details_json
				FROM repo_caches rc
				JOIN repos r ON r.id = rc.repo_id
				WHERE rc.repo_id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.RepoID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			if targetType == "contributor" {
				resp.Raw = row.ContributorsJSON
				resp.Metadata["source"] = "repo_caches.contributors_json"
			} else if targetType == "language" {
				resp.Raw = row.DetailsJSON
				resp.Metadata["source"] = "repo_caches.details_json"
			} else {
				resp.Raw = row.ReadmeContent
				resp.Metadata["source"] = "repo_caches.readme_content"
			}
		case "vex":
			var hasTable bool
			if err := db.WithContext(r.Context()).Raw("SELECT to_regclass('public.component_vex') IS NOT NULL").Scan(&hasTable).Error; err != nil {
				http.Error(w, "preview lookup failed", http.StatusInternalServerError)
				return
			}
			if !hasTable {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}

			vulnID := strings.TrimSpace(r.URL.Query().Get("vuln_id"))
			if vulnID == "" {
				http.Error(w, "vuln_id is required for vex preview", http.StatusBadRequest)
				return
			}
			var row struct {
				PURL          string `gorm:"column:p_url"`
				VulnID        string `gorm:"column:vuln_id"`
				Status        string `gorm:"column:status"`
				Justification string `gorm:"column:justification"`
				Detail        string `gorm:"column:detail"`
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					p_url AS p_url,
					vuln_id AS vuln_id,
					COALESCE(status, '') AS status,
					COALESCE(justification, '') AS justification,
					COALESCE(detail, '') AS detail
				FROM component_vex
				WHERE p_url = ? AND vuln_id = ?
				LIMIT 1
			`, sourceRef, vulnID).Scan(&row).Error
			if err != nil || row.PURL == "" || row.VulnID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			details, _ := fetchVulnerabilityDetails(r.Context(), row.VulnID)
			if repoID != "" {
				var repoRow struct {
					RepoID     string `gorm:"column:repo_id"`
					Provider   string `gorm:"column:provider"`
					ProviderID string `gorm:"column:provider_id"`
					BaseURL    string `gorm:"column:base_url"`
					OwnerPath  string `gorm:"column:owner_path"`
					Org        string `gorm:"column:org"`
					Slug       string `gorm:"column:slug"`
				}
				err := db.WithContext(r.Context()).Raw(`
					SELECT
						r.id AS repo_id,
						r.provider,
						COALESCE(pi.id, '') AS provider_id,
						COALESCE(pi.base_url, '') AS base_url,
						COALESCE(pi.owner_path, '') AS owner_path,
						r.org,
						r.slug
					FROM repos r
					LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
					WHERE r.id = ?
					LIMIT 1
				`, repoID).Scan(&repoRow).Error
				if err != nil {
					http.Error(w, "preview lookup failed", http.StatusInternalServerError)
					return
				}
				if repoRow.RepoID != "" {
					resp.RepoID = repoRow.RepoID
					resp.Provider = repoRow.Provider
					resp.Org = repoRow.Org
					resp.Slug = repoRow.Slug
					resp.Metadata["provider_id"] = repoRow.ProviderID
					resp.Metadata["base_url"] = repoRow.BaseURL
					resp.Metadata["owner_path"] = repoRow.OwnerPath
				}
			}
			rawParts := []string{
				fmt.Sprintf("PURL: %s", row.PURL),
				fmt.Sprintf("Vuln ID: %s", row.VulnID),
				"",
				fmt.Sprintf("Status: %s", row.Status),
				fmt.Sprintf("Justification: %s", row.Justification),
				fmt.Sprintf("VEX Detail: %s", row.Detail),
			}
			if details != nil && strings.TrimSpace(details.Summary) != "" {
				rawParts = append(rawParts, "Summary:", strings.TrimSpace(details.Summary))
			}
			if details != nil && strings.TrimSpace(details.Details) != "" {
				rawParts = append(rawParts, "", "OSV Details:", strings.TrimSpace(details.Details))
			}
			resp.Raw = strings.Join(rawParts, "\n")
			resp.Metadata["purl"] = row.PURL
			resp.Metadata["vuln_id"] = row.VulnID
			resp.Metadata["status"] = row.Status
			resp.Metadata["justification"] = row.Justification
			resp.Metadata["detail"] = row.Detail
			appendVulnMetadata(resp.Metadata, details, "", "")
		case "vuln":
			var hasTable bool
			if err := db.WithContext(r.Context()).Raw("SELECT to_regclass('public.component_vulnerabilities') IS NOT NULL").Scan(&hasTable).Error; err != nil {
				http.Error(w, "preview lookup failed", http.StatusInternalServerError)
				return
			}
			if !hasTable {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			vulnID := strings.TrimSpace(r.URL.Query().Get("vuln_id"))
			if vulnID == "" {
				http.Error(w, "vuln_id is required for vulnerability preview", http.StatusBadRequest)
				return
			}
			var row struct {
				PURL     string `gorm:"column:p_url"`
				VulnID   string `gorm:"column:vuln_id"`
				Summary  string `gorm:"column:summary"`
				Severity string `gorm:"column:severity"`
				FixedIn  string `gorm:"column:fixed_in"`
				Source   string `gorm:"column:source"`
				Checked  string `gorm:"column:checked"`
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					p_url AS p_url,
					vuln_id AS vuln_id,
					COALESCE(summary, '') AS summary,
					COALESCE(severity, '') AS severity,
					COALESCE(fixed_in, '') AS fixed_in,
					COALESCE(source, '') AS source,
					COALESCE(to_char(checked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS checked
				FROM component_vulnerabilities
				WHERE p_url = ? AND vuln_id = ?
				LIMIT 1
			`, sourceRef, vulnID).Scan(&row).Error
			if err != nil || row.PURL == "" || row.VulnID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			details, _ := fetchVulnerabilityDetails(r.Context(), row.VulnID)
			if repoID != "" {
				var repoRow struct {
					RepoID     string `gorm:"column:repo_id"`
					Provider   string `gorm:"column:provider"`
					ProviderID string `gorm:"column:provider_id"`
					BaseURL    string `gorm:"column:base_url"`
					OwnerPath  string `gorm:"column:owner_path"`
					Org        string `gorm:"column:org"`
					Slug       string `gorm:"column:slug"`
				}
				err := db.WithContext(r.Context()).Raw(`
					SELECT
						r.id AS repo_id,
						r.provider,
						COALESCE(pi.id, '') AS provider_id,
						COALESCE(pi.base_url, '') AS base_url,
						COALESCE(pi.owner_path, '') AS owner_path,
						r.org,
						r.slug
					FROM repos r
					LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
					WHERE r.id = ?
					LIMIT 1
				`, repoID).Scan(&repoRow).Error
				if err != nil {
					http.Error(w, "preview lookup failed", http.StatusInternalServerError)
					return
				}
				if repoRow.RepoID != "" {
					resp.RepoID = repoRow.RepoID
					resp.Provider = repoRow.Provider
					resp.Org = repoRow.Org
					resp.Slug = repoRow.Slug
					resp.Metadata["provider_id"] = repoRow.ProviderID
					resp.Metadata["base_url"] = repoRow.BaseURL
					resp.Metadata["owner_path"] = repoRow.OwnerPath
				}
			}
			effectiveFixed := row.FixedIn
			if strings.TrimSpace(effectiveFixed) == "" && details != nil {
				effectiveFixed = collectFixedVersions(details)
			}
			rawParts := []string{
				fmt.Sprintf("PURL: %s", row.PURL),
				fmt.Sprintf("Vuln ID: %s", row.VulnID),
				fmt.Sprintf("Source: %s", row.Source),
				fmt.Sprintf("Fixed in: %s", effectiveFixed),
				fmt.Sprintf("Checked at: %s", row.Checked),
				"",
			}
			if details != nil && strings.TrimSpace(details.Summary) != "" {
				rawParts = append(rawParts, "Summary:", strings.TrimSpace(details.Summary))
			} else if row.Summary != "" {
				rawParts = append(rawParts, "Summary:", row.Summary)
			}
			if details != nil && strings.TrimSpace(details.Details) != "" {
				rawParts = append(rawParts, "Details:", strings.TrimSpace(details.Details))
			}
			resp.Raw = strings.Join(rawParts, "\n")
			resp.Metadata["purl"] = row.PURL
			resp.Metadata["vuln_id"] = row.VulnID
			resp.Metadata["source"] = row.Source
			resp.Metadata["checked_at"] = row.Checked
			if strings.TrimSpace(row.Severity) != "" {
				resp.Metadata["severity"] = row.Severity
				if criticality := criticalityFromSeverityString(row.Severity); criticality != "" {
					resp.Metadata["criticality"] = criticality
				}
			}
			appendVulnMetadata(resp.Metadata, details, row.Summary, row.FixedIn)
		case "commit":
			var row struct {
				ID        string
				RepoID    string
				Provider  string
				Org       string
				Slug      string
				CommitSHA string
				Ref       string
				Raw       string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					c.id,
					c.repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(c.commit_sha, '') AS commit_sha,
					COALESCE(c.ref, '') AS ref,
					(COALESCE(c.commit_sha, '') || E'\n' || COALESCE(c.ref, '')) AS raw
				FROM repo_commits c
				JOIN repos r ON r.id = c.repo_id
				WHERE c.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["commit_sha"] = row.CommitSHA
			if row.Ref != "" {
				resp.Metadata["ref"] = row.Ref
			}
		case "repo":
			var row struct {
				ID       string
				Provider string
				Org      string
				Slug     string
				Details  string
				Readme   string
				Commits  string
				Contribs string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					r.id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.details_json, '') AS details,
					COALESCE(rc.readme_content, '') AS readme,
					COALESCE(rc.commits_json, '') AS commits,
					COALESCE(rc.contributors_json, '') AS contribs
				FROM repos r
				LEFT JOIN repo_caches rc ON rc.repo_id = r.id
				WHERE r.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.ID, row.Provider, row.Org, row.Slug
			resp.Raw = strings.TrimSpace(row.Details + "\n\n" + row.Readme + "\n\n" + row.Commits + "\n\n" + row.Contribs)
			resp.Metadata["repo"] = row.Org + "/" + row.Slug
			resp.Metadata["provider"] = row.Provider
		}

		if repoID != "" && resp.RepoID != "" && repoID != resp.RepoID {
			http.Error(w, "preview mismatch", http.StatusBadRequest)
			return
		}
		if len(resp.Raw) > 250000 {
			resp.Raw = resp.Raw[:250000] + "\n...truncated..."
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
