package uiapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

func detectSBOMFormat(payload []byte) string {
	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}

	if value, ok := decoded["bomFormat"].(string); ok && strings.EqualFold(value, "CycloneDX") {
		return "cyclonedx-json"
	}
	if _, ok := decoded["spdxVersion"].(string); ok {
		return "spdx-json"
	}

	return ""
}

// cycloneDXComponent holds the fields extracted from a CycloneDX component
// entry, mirroring what the sbom_component_view materialized view computes in SQL.
type cycloneDXComponent struct {
	BomRef  string
	Purl    string
	Name    string
	Version string
	Type    string
}

// countComponentsFromContent parses raw SBOM bytes and returns the component
// count without relying on the materialized view. Used as a fallback when the
// view has not yet been refreshed after a run completes.
func countComponentsFromContent(format string, content []byte) int {
	if len(content) == 0 {
		return 0
	}
	switch format {
	case "cyclonedx-json":
		var doc struct {
			Metadata struct {
				Component struct {
					BomRef string `json:"bom-ref"`
					Purl   string `json:"purl"`
				} `json:"component"`
			} `json:"metadata"`
			Components []struct {
				BomRef string `json:"bom-ref"`
				Purl   string `json:"purl"`
			} `json:"components"`
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(content, &doc); err != nil {
			return 0
		}
		rootRef := doc.Metadata.Component.BomRef
		rootPurl := doc.Metadata.Component.Purl
		if rootRef == "" {
			rootRef = rootPurl
		}
		if rootRef == "" {
			rootRef = cycloneDXDependencyGraphRoot(doc.Components, doc.Dependencies)
		}
		count := 0
		for _, c := range doc.Components {
			componentRef := firstNonEmpty(c.BomRef, c.Purl)
			if rootRef != "" && (componentRef == rootRef || (rootPurl != "" && c.Purl == rootPurl)) {
				continue
			}
			count++
		}
		return count
	case "spdx-json":
		var doc struct {
			Packages []struct{} `json:"packages"`
		}
		if err := json.Unmarshal(content, &doc); err != nil {
			return 0
		}
		n := len(doc.Packages)
		if n > 0 {
			return n - 1
		}
		return 0
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// cycloneDXDependencyGraphRoot returns the bom-ref of the root component by
// finding the entry in dependencies.ref that no other component depends on.
// This handles SBOMs that omit metadata.component or use mismatched bom-refs.
func cycloneDXDependencyGraphRoot(
	components []struct {
		BomRef string `json:"bom-ref"`
		Purl   string `json:"purl"`
	},
	dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	},
) string {
	if len(components) == 0 || len(dependencies) == 0 {
		return ""
	}
	componentRefs := make(map[string]bool, len(components))
	for _, c := range components {
		if ref := firstNonEmpty(c.BomRef, c.Purl); ref != "" {
			componentRefs[ref] = true
		}
	}
	dependedOn := make(map[string]bool)
	for _, d := range dependencies {
		for _, dep := range d.DependsOn {
			dependedOn[dep] = true
		}
	}
	for _, d := range dependencies {
		if componentRefs[d.Ref] && !dependedOn[d.Ref] {
			return d.Ref
		}
	}
	return ""
}

// extractCycloneDXComponents parses a CycloneDX JSON SBOM and returns the
// list of components declared in the top-level "components" array.
func extractCycloneDXComponents(payload []byte) ([]cycloneDXComponent, error) {
	var doc struct {
		Components []struct {
			BomRef  string `json:"bom-ref"`
			Purl    string `json:"purl"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	out := make([]cycloneDXComponent, 0, len(doc.Components))
	for _, c := range doc.Components {
		out = append(out, cycloneDXComponent{
			BomRef:  c.BomRef,
			Purl:    c.Purl,
			Name:    c.Name,
			Version: c.Version,
			Type:    c.Type,
		})
	}
	return out, nil
}

// sbomComponentCount returns the non-root component count for an SBOM.
// It prefers the materialized view when a root component was detected (is_root=true),
// which means the count excludes the root. If no root was detected in the view (all
// rows have is_root=false), it falls back to parsing the SBOM content directly —
// which uses the dependency graph to identify and exclude the root.
func sbomComponentCount(ctx context.Context, db *gorm.DB, sbomID, format string, content []byte) int64 {
	var rootCount int64
	_ = db.WithContext(ctx).Table("sbom_component_view").
		Where("sbom_id = ? AND is_root = true", sbomID).
		Count(&rootCount)

	var nonRootCount int64
	_ = db.WithContext(ctx).Table("sbom_component_view").
		Where("sbom_id = ? AND is_root = false", sbomID).
		Count(&nonRootCount)

	if nonRootCount > 0 && rootCount > 0 {
		return nonRootCount
	}
	if parsed := int64(countComponentsFromContent(format, content)); parsed > 0 {
		return parsed
	}
	return nonRootCount
}

// SBOMDownloadHandler downloads an SBOM by ID.
// GET /api/sboms/{id}/download
func SBOMDownloadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		sbomID := r.PathValue("id")
		if sbomID == "" {
			http.Error(w, "sbom ID required", http.StatusBadRequest)
			return
		}
		if ok, err := canReadSBOM(r, db, sbomID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		sbom, err := artifacts.FindSBOM(r.Context(), db, sbomID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "sbom not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to fetch sbom", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=sbom.json")
		w.Write(sbom.ContentBytes)
	}
}

// SBOMGetHandler returns SBOM metadata by ID.
// GET /api/sboms/{id}
func SBOMGetHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		sbomID := r.PathValue("id")
		if sbomID == "" {
			http.Error(w, "sbom ID required", http.StatusBadRequest)
			return
		}
		if ok, err := canReadSBOM(r, db, sbomID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		sbom, err := artifacts.FindSBOM(r.Context(), db, sbomID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "sbom not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to fetch sbom", http.StatusInternalServerError)
			return
		}

		componentCount := sbomComponentCount(r.Context(), db, sbomID, sbom.Format, sbom.ContentBytes)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":              sbom.ID,
			"format":          sbom.Format,
			"created_at":      sbom.CreatedAt,
			"component_count": componentCount,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
