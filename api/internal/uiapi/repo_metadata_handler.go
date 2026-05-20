package uiapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/secretprobe"
	"gorm.io/gorm"
)

const repoMetadataCacheTTL = 15 * time.Minute

type repoMetadataCacheEntry struct {
	CachedAt time.Time            `json:"cached_at"`
	Response RepoMetadataResponse `json:"response"`
}

// RepoMetadataHandler returns a unified metadata response for a repo.
// GET /api/repos/metadata?repo_id=<uuid>
func RepoMetadataHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}
		if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		cacheKey := "repo:metadata:" + repoID
		if cached, ok, _ := cache.GetJSON[repoMetadataCacheEntry](r.Context(), c, cacheKey); ok && !repoMetadataCacheStale(r, db, repoID, cached.CachedAt) {
			writeJSON(w, http.StatusOK, cached.Response)
			return
		}

		repoMeta, repoDBID := loadRepoMetadata(r, db, repoID)
		latestCommit := loadRepoLatestCommit(r, db, repoDBID)
		runs := loadRepoRuns(r, db, repoDBID)
		sbom, sbomComponentCount := loadRepoSBOM(r, db, repoDBID)
		deps := loadRepoDependencies(r, db, repoDBID, sbomComponentCount, runs.Latest)
		secrets := loadRepoSecrets(r, db, repoID, runs.Latest)
		vulnerabilities := loadRepoVulnerabilities(r, db, repoDBID)

		resp := RepoMetadataResponse{
			Repo:            repoMeta,
			LatestCommit:    latestCommit,
			Runs:            runs,
			SBOM:            sbom,
			Dependencies:    deps,
			Secrets:         secrets,
			Hygiene:         RepoMetadataHygiene{},
			Vulnerabilities: vulnerabilities,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, repoMetadataCacheEntry{
			CachedAt: time.Now().UTC(),
			Response: resp,
		}, repoMetadataCacheTTL)
		writeJSON(w, http.StatusOK, resp)
	}
}

func repoMetadataCacheStale(r *http.Request, db *gorm.DB, repoID string, cachedAt time.Time) bool {
	if cachedAt.IsZero() {
		return true
	}

	var row struct {
		Latest time.Time `gorm:"column:latest"`
	}
	err := db.WithContext(r.Context()).Raw(`
		SELECT GREATEST(
			COALESCE((SELECT MAX(created_at) FROM repo_commits WHERE repo_id = @repo_id), TIMESTAMPTZ 'epoch'),
			COALESCE((SELECT MAX(finished_at) FROM jobs WHERE type = 'CREATE_RUN' AND payload->>'repo_id' = @repo_id), TIMESTAMPTZ 'epoch'),
			COALESCE((SELECT MAX(created_at) FROM run_secrets WHERE repo_id = @repo_id), TIMESTAMPTZ 'epoch'),
			COALESCE((
				SELECT MAX(sb.created_at)
				FROM sbom_bindings sb
				JOIN repo_commits rc ON rc.id = sb.asset_ref_id AND sb.asset_type = 'REPO_COMMIT'
				WHERE rc.repo_id = @repo_id
			), TIMESTAMPTZ 'epoch'),
			COALESCE((SELECT MAX(scanned_at) FROM sbom_scan_results WHERE repo_id = @repo_id), TIMESTAMPTZ 'epoch'),
			COALESCE((SELECT refreshed_at FROM materialized_view_refreshes WHERE name = 'sbom_component_view'), TIMESTAMPTZ 'epoch'),
			COALESCE((SELECT refreshed_at FROM materialized_view_refreshes WHERE name = 'view_unified_repositories_vulnerabilities'), TIMESTAMPTZ 'epoch')
		) AS latest
	`, map[string]any{"repo_id": repoID}).Scan(&row).Error
	if err != nil {
		return true
	}
	return cachedAt.UTC().Before(row.Latest.UTC())
}

func loadRepoMetadata(r *http.Request, db *gorm.DB, repoID string) (RepoMetadataRepo, string) {
	meta := RepoMetadataRepo{ID: repoID}

	var repo struct {
		ID                 string
		Provider           string
		ProviderInstanceID string
		Org                string
		Slug               string
		ProviderUpdatedAt  *time.Time
	}
	if err := db.WithContext(r.Context()).Table("repos").
		Select("id, provider, provider_instance_id, org, slug, provider_updated_at").
		Where("id = ?", repoID).
		First(&repo).Error; err != nil {
		return meta, ""
	}

	meta.Provider = repo.Provider
	meta.Org = repo.Org
	meta.Slug = repo.Slug
	if repo.ProviderUpdatedAt != nil && !repo.ProviderUpdatedAt.IsZero() {
		meta.UpdatedAt = repo.ProviderUpdatedAt.UTC().Format(time.RFC3339)
	}

	if repo.ProviderInstanceID != "" {
		meta.ProviderID = repo.ProviderInstanceID
		var baseURL string
		_ = db.WithContext(r.Context()).Table("provider_instances").
			Select("base_url").
			Where("id = ?", repo.ProviderInstanceID).
			Scan(&baseURL).Error
		meta.ProviderBaseURL = baseURL
	}

	return meta, repo.ID
}

func loadRepoLatestCommit(r *http.Request, db *gorm.DB, repoDBID string) *RepoMetadataCommit {
	if repoDBID == "" {
		return nil
	}

	var commit struct {
		CommitSHA string
		CreatedAt time.Time
	}
	if err := db.WithContext(r.Context()).Table("repo_commits").
		Select("commit_sha, created_at").
		Where("repo_id = ?", repoDBID).
		Order("created_at DESC").
		Limit(1).
		Scan(&commit).Error; err != nil || commit.CommitSHA == "" {
		return nil
	}

	return &RepoMetadataCommit{
		SHA:         commit.CommitSHA,
		CommittedAt: commit.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func loadRepoRuns(r *http.Request, db *gorm.DB, repoDBID string) RepoMetadataRuns {
	response := RepoMetadataRuns{
		Total:    0,
		Timeline: []RepoMetadataRunSummary{},
	}
	if repoDBID == "" {
		return response
	}

	query := db.WithContext(r.Context()).
		Table("jobs").
		Joins(`JOIN repo_commits rc
			ON rc.repo_id = ?
			AND rc.commit_sha = COALESCE(NULLIF(jobs.commit_hash, ''), NULLIF(jobs.payload->>'commit_sha', ''))`, repoDBID).
		Where("jobs.type = ?", "CREATE_RUN")

	query.Where("finished_at IS NOT NULL").Count(&response.Total)

	var rows []struct {
		ID         string
		Status     string
		Payload    []byte
		CommitHash string
		CreatedAt  time.Time
		LockedAt   *time.Time
		FinishedAt *time.Time
		Result     []byte
	}
	if err := query.Select("jobs.id, jobs.status, jobs.payload, jobs.commit_hash, jobs.created_at, jobs.locked_at, jobs.finished_at, jobs.result").
		Order("jobs.created_at DESC").
		Limit(10).
		Find(&rows).Error; err != nil {
		return response
	}

	for _, row := range rows {
		status := row.Status
		if status == string(jobs.JobStatusSucceeded) || status == string(jobs.JobStatusRunning) || status == string(jobs.JobStatusQueued) {
			if resultMap, err := parseRunResultMap(row.Result); err == nil {
				events, podStatus, ok, err := loadPersistedK8sSnapshotFromResult(resultMap)
				if err == nil && ok {
					if failed, _ := inferK8sFailure(events, podStatus); failed {
						status, _, _ = correctRunStatusFromSnapshot(r.Context(), db, row.ID, status, events, podStatus)
					}
				}
			}
		}

		commitSHA := row.CommitHash
		if commitSHA == "" && len(row.Payload) > 0 {
			var payload jobs.CreateRunPayload
			if err := json.Unmarshal(row.Payload, &payload); err == nil {
				commitSHA = payload.CommitSHA
			}
		}

		summary := RepoMetadataRunSummary{
			ID:         row.ID,
			Status:     status,
			CommitSHA:  commitSHA,
			StartedAt:  formatTimePtr(row.LockedAt),
			FinishedAt: formatTimePtr(row.FinishedAt),
		}
		if row.LockedAt != nil && row.FinishedAt != nil {
			summary.DurationMs = row.FinishedAt.Sub(*row.LockedAt).Milliseconds()
		}
		summary.Artifacts = loadRunArtifacts(r, db, row.ID, repoDBID, commitSHA)
		response.Timeline = append(response.Timeline, summary)
	}

	if len(response.Timeline) > 0 {
		response.Latest = &response.Timeline[0]
	}

	return response
}

func loadRunArtifacts(r *http.Request, db *gorm.DB, runID, repoDBID, commitSHA string) []string {
	runArtifacts := make([]string, 0, 3)

	var secretsCount int64
	if err := db.WithContext(r.Context()).Table("run_secrets").
		Where("run_id = ?", runID).
		Count(&secretsCount).Error; err == nil && secretsCount > 0 {
		runArtifacts = append(runArtifacts, "secrets")
	}

	var manifestCount int64
	if err := db.WithContext(r.Context()).Table("manifests").
		Where("run_id = ?", runID).
		Count(&manifestCount).Error; err == nil && manifestCount > 0 {
		runArtifacts = append(runArtifacts, "manifests")
	}

	if repoDBID == "" {
		return runArtifacts
	}

	var sbomID string
	if commitSHA == "" {
		return runArtifacts
	}

	if err := db.WithContext(r.Context()).Table("sbom_bindings sb").
		Select("sb.sbom_id").
		Joins("JOIN repo_commits rc ON rc.id = sb.asset_ref_id").
		Where("sb.asset_type = ? AND rc.repo_id = ? AND rc.commit_sha = ?", artifacts.AssetTypeRepoCommit, repoDBID, commitSHA).
		Order("sb.created_at DESC").
		Limit(1).
		Scan(&sbomID).Error; err == nil && sbomID != "" {
		runArtifacts = append(runArtifacts, "sbom")
	}

	return runArtifacts
}

func loadRepoSBOM(r *http.Request, db *gorm.DB, repoDBID string) (RepoMetadataSBOM, int64) {
	var sbomID string
	if repoDBID != "" {
		var commitID string
		if err := db.WithContext(r.Context()).Table("repo_commits").
			Select("id").
			Where("repo_id = ?", repoDBID).
			Order("created_at DESC").
			Limit(1).
			Scan(&commitID).Error; err == nil && commitID != "" {
			_ = db.WithContext(r.Context()).Table("sbom_bindings").
				Select("sbom_id").
				Where("asset_ref_id = ?", commitID).
				Order("created_at DESC").
				Limit(1).
				Scan(&sbomID).Error
		}
	}

	if sbomID == "" {
		return RepoMetadataSBOM{}, 0
	}

	var sbom struct {
		ID           string
		Format       string
		CreatedAt    time.Time
		ContentBytes []byte
	}
	if err := db.WithContext(r.Context()).Table("sboms").
		Select("id, format, created_at, content_bytes").
		Where("id = ?", sbomID).
		First(&sbom).Error; err != nil {
		return RepoMetadataSBOM{}, 0
	}

	componentCount := sbomComponentCount(r.Context(), db, sbomID, sbom.Format, sbom.ContentBytes)

	return RepoMetadataSBOM{
		Latest: &RepoMetadataSBOMItem{
			ID:             sbom.ID,
			CreatedAt:      sbom.CreatedAt.UTC().Format(time.RFC3339),
			Format:         sbom.Format,
			ComponentCount: componentCount,
			DownloadURL:    "/api/sboms/" + sbom.ID + "/download",
		},
	}, componentCount
}

func loadRepoDependencies(r *http.Request, db *gorm.DB, repoDBID string, sbomComponentCount int64, latestRun *RepoMetadataRunSummary) RepoMetadataDependencies {
	deps := RepoMetadataDependencies{
		FromSBOM: sbomComponentCount,
	}

	if repoDBID == "" || latestRun == nil {
		deps.Total = sbomComponentCount
		return deps
	}

	var manifestCount int64
	if err := db.WithContext(r.Context()).Table("manifest_dependencies md").
		Joins("JOIN manifests m ON m.id = md.manifest_id").
		Where("m.repo_id = ? AND m.run_id = ?", repoDBID, latestRun.ID).
		Count(&manifestCount).Error; err == nil {
		deps.FromManifest = manifestCount
	}

	deps.Total = deps.FromSBOM + deps.FromManifest

	return deps
}

func loadRepoSecrets(r *http.Request, db *gorm.DB, repoID string, latestRun *RepoMetadataRunSummary) RepoMetadataSecrets {
	runID := ""
	if latestRun != nil {
		runID = latestRun.ID
	}

	var row struct {
		Findings  string
		CreatedAt time.Time
	}
	// Query by repo_id (same as secrets/list) to ensure consistent results.
	res := db.WithContext(r.Context()).Table("run_secrets").
		Select("findings::text as findings, created_at").
		Where("repo_id = ?", repoID).
		Order("created_at DESC").
		Limit(1).
		Scan(&row)
	if res.Error != nil || res.RowsAffected == 0 || row.CreatedAt.IsZero() {
		return RepoMetadataSecrets{LatestRunID: runID}
	}

	if row.Findings == "" {
		return RepoMetadataSecrets{
			LatestRunID:   runID,
			LastScannedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	var raw []struct {
		Match  string `json:"Match"`
		Secret string `json:"Secret"`
	}
	if err := json.Unmarshal([]byte(row.Findings), &raw); err != nil {
		return RepoMetadataSecrets{
			LatestRunID:   runID,
			LatestCount:   int64(len(raw)),
			LastScannedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	// Compute hashes and look up dismissed secrets.
	hashes := make([]string, len(raw))
	for i, f := range raw {
		s := secretprobe.ExtractSecret(f.Match)
		if f.Secret != "" {
			s = secretprobe.ExtractSecret(f.Secret)
		}
		hashes[i] = secretprobe.SecretHash(s)
	}
	dismissed := map[string]bool{}
	if len(hashes) > 0 {
		var dismissedHashes []string
		db.WithContext(r.Context()).
			Model(&secretprobe.SecretDismissal{}).
			Where("secret_hash IN ?", hashes).
			Pluck("secret_hash", &dismissedHashes)
		for _, h := range dismissedHashes {
			dismissed[h] = true
		}
	}

	count := int64(0)
	for _, h := range hashes {
		if !dismissed[h] {
			count++
		}
	}

	return RepoMetadataSecrets{
		LatestRunID:   runID,
		LatestCount:   count,
		LastScannedAt: row.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func loadRepoVulnerabilities(r *http.Request, db *gorm.DB, repoDBID string) RepoMetadataVulnerabilities {
	if repoDBID == "" {
		return RepoMetadataVulnerabilities{}
	}

	var summary RepoMetadataVulnSummary
	db.WithContext(r.Context()).Raw(`
		SELECT
			COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
			COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium,
			COUNT(*) FILTER (WHERE severity = 'LOW')      AS low,
			COUNT(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW')) AS unknown
		FROM view_unified_repositories_vulnerabilities
		WHERE repo_id = ?
	`, repoDBID).Scan(&summary)

	if summary.Critical == 0 && summary.High == 0 && summary.Medium == 0 && summary.Low == 0 && summary.Unknown == 0 {
		return RepoMetadataVulnerabilities{}
	}

	return RepoMetadataVulnerabilities{
		Summary: &summary,
	}
}
