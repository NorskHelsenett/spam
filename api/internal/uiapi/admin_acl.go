package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Admin grant CRUD API. Admin-only. Audit-wrapped at the router.
//
//   GET    /api/admin/acl/grants                 list all grants
//   POST   /api/admin/acl/grants                 create grant
//   DELETE /api/admin/acl/grants/{id}            delete grant by id
//
// Grants are rows in the acl_grants table (see internal/acl). Every
// row is fail-closed validated via DB CHECK constraints AND a second
// pass here so we fail fast with a helpful message instead of a
// Postgres error code.

type grantResponse struct {
	ID              string          `json:"id"`
	SubjectType     string          `json:"subject_type"`
	SubjectID       string          `json:"subject_id"`
	ScopeType       string          `json:"scope_type"`
	ScopePattern    json.RawMessage `json:"scope_pattern"`
	Action          string          `json:"action"`
	Source          string          `json:"source"`
	CreatedAt       time.Time       `json:"created_at"`
	CreatedByUserID string          `json:"created_by,omitempty"`
}

type createGrantRequest struct {
	SubjectType  string             `json:"subject_type"`
	SubjectID    string             `json:"subject_id"`
	ScopeType    string             `json:"scope_type"`
	ScopePattern *acl.ScopePattern  `json:"scope_pattern"`
	Action       string             `json:"action"`
}

// AdminACLGrantsListHandler returns every row in acl_grants, newest first.
// GET /api/admin/acl/grants
func AdminACLGrantsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var rows []acl.Grant
		if err := db.WithContext(r.Context()).
			Order("created_at desc").
			Find(&rows).Error; err != nil {
			http.Error(w, "failed to list grants", http.StatusInternalServerError)
			return
		}

		out := make([]grantResponse, 0, len(rows))
		for _, g := range rows {
			out = append(out, grantResponse{
				ID:              g.ID,
				SubjectType:     g.SubjectType,
				SubjectID:       g.SubjectID,
				ScopeType:       g.ScopeType,
				ScopePattern:    json.RawMessage(g.ScopePattern),
				Action:          g.Action,
				Source:          g.Source,
				CreatedAt:       g.CreatedAt,
				CreatedByUserID: g.CreatedByUserID,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// AdminACLGrantsCreateHandler inserts a new explicit grant.
// POST /api/admin/acl/grants
func AdminACLGrantsCreateHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin := requireAdmin(w, r, authService)
		if admin == nil {
			return
		}

		var req createGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		grant, err := buildGrantFromRequest(req, admin.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := db.WithContext(r.Context()).Create(&grant).Error; err != nil {
			// Unique-index collision is expected when an admin re-adds
			// an identical grant; normalise to 409 so the UI can show
			// a sensible message.
			if strings.Contains(err.Error(), "ux_acl_grant_identity") {
				http.Error(w, "grant already exists", http.StatusConflict)
				return
			}
			http.Error(w, "failed to create grant", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, grantResponse{
			ID:              grant.ID,
			SubjectType:     grant.SubjectType,
			SubjectID:       grant.SubjectID,
			ScopeType:       grant.ScopeType,
			ScopePattern:    json.RawMessage(grant.ScopePattern),
			Action:          grant.Action,
			Source:          grant.Source,
			CreatedAt:       grant.CreatedAt,
			CreatedByUserID: grant.CreatedByUserID,
		})
	}
}

// AdminACLGrantsDeleteHandler removes a grant by id. Deleting a
// migration grant is allowed — that's how admins "tighten" from
// grandfathered wildcard access to explicit.
// DELETE /api/admin/acl/grants/{id}
func AdminACLGrantsDeleteHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		res := db.WithContext(r.Context()).Delete(&acl.Grant{}, "id = ?", id)
		if res.Error != nil {
			http.Error(w, "failed to delete grant", http.StatusInternalServerError)
			return
		}
		if res.RowsAffected == 0 {
			http.Error(w, "grant not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// buildGrantFromRequest validates and normalises a CreateGrantRequest
// into an acl.Grant ready to insert. Admin-created grants are always
// source='explicit'; 'migration' and 'ingest_default' are reserved
// for the migration SQL and the provider-upsert path respectively.
func buildGrantFromRequest(req createGrantRequest, createdBy string) (acl.Grant, error) {
	subjectType := strings.TrimSpace(req.SubjectType)
	if subjectType != acl.SubjectUser && subjectType != acl.SubjectGroup {
		return acl.Grant{}, errors.New("subject_type must be 'user' or 'group'")
	}
	subjectID := strings.TrimSpace(req.SubjectID)
	if subjectID == "" {
		return acl.Grant{}, errors.New("subject_id required")
	}
	scopeType := strings.TrimSpace(req.ScopeType)
	switch scopeType {
	case acl.ScopeRepo, acl.ScopeCluster, acl.ScopeImage:
	default:
		return acl.Grant{}, errors.New("scope_type must be 'repo', 'cluster', or 'image'")
	}
	if req.ScopePattern == nil {
		return acl.Grant{}, errors.New("scope_pattern required (use {} for wildcard)")
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = acl.ActionRead
	}
	if action != acl.ActionRead {
		return acl.Grant{}, errors.New("action must be 'read'")
	}

	raw, err := json.Marshal(req.ScopePattern)
	if err != nil {
		return acl.Grant{}, errors.New("could not encode scope_pattern")
	}

	return acl.Grant{
		ID:              uuid.NewString(),
		SubjectType:     subjectType,
		SubjectID:       subjectID,
		ScopeType:       scopeType,
		ScopePattern:    datatypes.JSON(raw),
		Action:          action,
		Source:          acl.SourceExplicit,
		CreatedAt:       time.Now().UTC(),
		CreatedByUserID: createdBy,
	}, nil
}
