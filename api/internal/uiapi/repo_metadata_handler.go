package uiapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

const repoMetadataCacheTTL = 30 * time.Second

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

		cacheKey := "repo:metadata:" + repoID
		if cached, ok, _ := cache.GetJSON[RepoMetadataResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		repoMeta, repoDBID := loadRepoMetadata(r, db, repoID)
		latestCommit := loadRepoLatestCommit(r, db, repoDBID)
		runs := loadRepoRuns(r, db, repoMeta.Org, repoMeta.Slug, repoDBID)
		sbom, sbomComponentCount := loadRepoSBOM(r, db, repoDBID)
		deps := loadRepoDependencies(r, db, repoDBID, sbomComponentCount)
		secrets := loadRepoSecrets(r, db, runs.Latest)

		resp := RepoMetadataResponse{
			Repo:            repoMeta,
			LatestCommit:    latestCommit,
			Runs:            runs,
			SBOM:            sbom,
			Dependencies:    deps,
			Secrets:         secrets,
			Hygiene:         RepoMetadataHygiene{},
			Vulnerabilities: RepoMetadataVulnerabilities{},
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, repoMetadataCacheTTL)
		writeJSON(w, http.StatusOK, resp)
	}
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

func loadRepoRuns(r *http.Request, db *gorm.DB, org, slug string, repoDBID string) RepoMetadataRuns {
	response := RepoMetadataRuns{
		Total:    0,
		Timeline: []RepoMetadataRunSummary{},
	}

	query := db.WithContext(r.Context()).Table("jobs").Where("type = ?", "CREATE_RUN")
	if org != "" && slug != "" {
		query = query.Where("payload::text LIKE ?", "%"+org+"/"+slug+"%")
	}

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
	if err := query.Select("id, status, payload, commit_hash, created_at, locked_at, finished_at, result").
		Order("created_at DESC").
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
		summary.Artifacts = loadRunArtifacts(r, db, row.ID, repoDBID)
		response.Timeline = append(response.Timeline, summary)
	}

	if len(response.Timeline) > 0 {
		response.Latest = &response.Timeline[0]
	}

	return response
}

func loadRunArtifacts(r *http.Request, db *gorm.DB, runID, repoDBID string) []string {
	artifacts := make([]string, 0, 3)

	var secretsCount int64
	if err := db.WithContext(r.Context()).Table("run_secrets").
		Where("run_id = ?", runID).
		Count(&secretsCount).Error; err == nil && secretsCount > 0 {
		artifacts = append(artifacts, "secrets")
	}

	if repoDBID == "" {
		return artifacts
	}

	var sbomID string
	var commitID string
	if err := db.WithContext(r.Context()).Table("repo_commits").
		Select("id").
		Where("repo_id = ?", repoDBID).
		Order("created_at DESC").
		Limit(1).
		Scan(&commitID).Error; err != nil || commitID == "" {
		return artifacts
	}

	if err := db.WithContext(r.Context()).Table("sbom_bindings").
		Select("sbom_id").
		Where("asset_ref_id = ?", commitID).
		Order("created_at DESC").
		Limit(1).
		Scan(&sbomID).Error; err == nil && sbomID != "" {
		artifacts = append(artifacts, "sbom")
	}

	return artifacts
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
		ID        string
		Format    string
		CreatedAt time.Time
	}
	if err := db.WithContext(r.Context()).Table("sboms").
		Select("id, format, created_at").
		Where("id = ?", sbomID).
		First(&sbom).Error; err != nil {
		return RepoMetadataSBOM{}, 0
	}

	var componentCount int64
	if err := db.WithContext(r.Context()).Table("sbom_component_view").
		Where("sbom_id = ? AND is_root = false", sbomID).
		Count(&componentCount).Error; err != nil {
		componentCount = 0
	}

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

func loadRepoDependencies(r *http.Request, db *gorm.DB, repoDBID string, sbomComponentCount int64) RepoMetadataDependencies {
	deps := RepoMetadataDependencies{
		FromSBOM: sbomComponentCount,
	}

	if repoDBID == "" {
		deps.Total = sbomComponentCount
		return deps
	}

	var manifestCount int64
	if err := db.WithContext(r.Context()).Table("manifest_dependencies md").
		Joins("JOIN manifests m ON m.id = md.manifest_id").
		Where("m.repo_id = ?", repoDBID).
		Count(&manifestCount).Error; err == nil {
		deps.FromManifest = manifestCount
	}

	if deps.FromManifest > deps.FromSBOM {
		deps.Total = deps.FromManifest
	} else {
		deps.Total = deps.FromSBOM
	}

	return deps
}

func loadRepoSecrets(r *http.Request, db *gorm.DB, latestRun *RepoMetadataRunSummary) RepoMetadataSecrets {
	if latestRun == nil {
		return RepoMetadataSecrets{}
	}

	var secret struct {
		Count     int64
		CreatedAt time.Time
	}
	if err := db.WithContext(r.Context()).Table("run_secrets").
		Select("finding_count as count, created_at").
		Where("run_id = ?", latestRun.ID).
		Order("created_at DESC").
		Limit(1).
		Scan(&secret).Error; err != nil || secret.CreatedAt.IsZero() {
		return RepoMetadataSecrets{LatestRunID: latestRun.ID}
	}

	return RepoMetadataSecrets{
		LatestRunID:   latestRun.ID,
		LatestCount:   secret.Count,
		LastScannedAt: secret.CreatedAt.UTC().Format(time.RFC3339),
	}
}
