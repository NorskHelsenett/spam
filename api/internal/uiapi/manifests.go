package uiapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// ManifestSummary is the API response for a manifest
type ManifestSummary struct {
	manifests.Manifest
	DependencyCount int `json:"dependency_count"`
}

// ManifestsListResponse is the API response for listing manifests
type ManifestsListResponse struct {
	Manifests  []ManifestSummary `json:"manifests"`
	Total      int64             `json:"total"`
	Page       int               `json:"page"`
	PerPage    int               `json:"per_page"`
	TotalPages int               `json:"total_pages"`
}

// ManifestsListHandler returns paginated manifests
func ManifestsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if perPage < 1 || perPage > 100 {
			perPage = 20
		}
		repoID := r.URL.Query().Get("repo_id")
		runID := r.URL.Query().Get("run_id")

		if repoID != "" {
			if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		}
		readable, unrestricted, err := readableRepoIDSet(r, db)
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}

		// Count total
		var total int64
		countQuery := db.WithContext(r.Context()).Model(&manifests.Manifest{})
		if repoID != "" {
			countQuery = countQuery.Where("repo_id = ?", repoID)
		}
		if runID != "" {
			countQuery = countQuery.Where("run_id = ?", runID)
		}
		if !unrestricted {
			if len(readable) == 0 {
				writeJSON(w, http.StatusOK, ManifestsListResponse{
					Manifests: []ManifestSummary{}, Total: 0, Page: page, PerPage: perPage, TotalPages: 0,
				})
				return
			}
			ids := make([]string, 0, len(readable))
			for id := range readable {
				ids = append(ids, id)
			}
			countQuery = countQuery.Where("repo_id IN ?", ids)
		}
		if err := countQuery.Count(&total).Error; err != nil {
			log.Printf("manifests count error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Query manifests with dependency counts
		query := `
			SELECT m.*, COUNT(d.id) as dependency_count
			FROM manifests m
			LEFT JOIN manifest_dependencies d ON d.manifest_id = m.id
		`
		args := []interface{}{}
		var wheres []string
		if repoID != "" {
			wheres = append(wheres, "m.repo_id = ?")
			args = append(args, repoID)
		} else if runID != "" {
			wheres = append(wheres, "m.run_id = ?")
			args = append(args, runID)
		}
		if !unrestricted {
			ids := make([]string, 0, len(readable))
			for id := range readable {
				ids = append(ids, id)
			}
			wheres = append(wheres, "m.repo_id IN ?")
			args = append(args, ids)
		}
		whereClause := ""
		if len(wheres) > 0 {
			whereClause = " WHERE " + strings.Join(wheres, " AND ")
		}
		query += whereClause + " GROUP BY m.id ORDER BY m.created_at DESC LIMIT ? OFFSET ?"

		offset := (page - 1) * perPage
		args = append(args, perPage, offset)

		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("manifests query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		manifestsList := make([]ManifestSummary, 0)
		for rows.Next() {
			var m ManifestSummary
			if err := db.ScanRows(rows, &m); err != nil {
				log.Printf("manifests scan error: %v", err)
				continue
			}
			manifestsList = append(manifestsList, m)
		}

		totalPages := int(total) / perPage
		if int(total)%perPage > 0 {
			totalPages++
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ManifestsListResponse{
			Manifests:  manifestsList,
			Total:      total,
			Page:       page,
			PerPage:    perPage,
			TotalPages: totalPages,
		})
	}
}

// ManifestGetHandler returns a single manifest with dependencies
func ManifestGetHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		manifestID := chi.URLParam(r, "id")
		if manifestID == "" {
			http.Error(w, "missing manifest ID", http.StatusBadRequest)
			return
		}

		var manifest manifests.Manifest
		if err := db.WithContext(r.Context()).Where("id = ?", manifestID).First(&manifest).Error; err != nil {
			notFoundOrForbidden(w)
			return
		}
		if ok, err := canReadRepoByID(r, db, manifest.RepoID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		// Get dependencies
		var deps []manifests.ManifestDependency
		if err := db.WithContext(r.Context()).Where("manifest_id = ?", manifestID).Find(&deps).Error; err != nil {
			log.Printf("failed to load dependencies: %v", err)
		}

		response := struct {
			manifests.Manifest
			Dependencies []manifests.ManifestDependency `json:"dependencies"`
		}{
			Manifest:     manifest,
			Dependencies: deps,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// DependencySearchHandler searches for dependencies across all manifests
func DependencySearchHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		query := r.URL.Query().Get("q")
		ecosystem := r.URL.Query().Get("ecosystem")

		if query == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}

		// Search dependencies, constrained to manifests from readable
		// repos. Admins and wildcard-grant callers skip the restrict
		// subquery; others see only their scope.
		dbQuery := db.WithContext(r.Context()).
			Model(&manifests.ManifestDependency{}).
			Where("name ILIKE ?", "%"+query+"%")

		if ecosystem != "" {
			dbQuery = dbQuery.Where("ecosystem = ?", ecosystem)
		}

		readable, unrestricted, err := readableRepoIDSet(r, db)
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		if !unrestricted {
			if len(readable) == 0 {
				json.NewEncoder(w).Encode([]manifests.ManifestDependency{})
				return
			}
			ids := make([]string, 0, len(readable))
			for id := range readable {
				ids = append(ids, id)
			}
			dbQuery = dbQuery.Where("manifest_id IN (SELECT id FROM manifests WHERE repo_id IN ?)", ids)
		}

		var deps []manifests.ManifestDependency
		if err := dbQuery.Limit(100).Find(&deps).Error; err != nil {
			log.Printf("dependency search error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deps)
	}
}
