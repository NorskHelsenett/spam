package uiapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/vulnmeta"
	"gorm.io/gorm"
)

// VulnClusterPresence is one cluster (+ namespace) where an affected
// image is actively running. container_count summarises how many
// pods across the namespace currently expose the vulnerable digest.
type VulnClusterPresence struct {
	ClusterID      string `json:"cluster_id"`
	Cluster        string `json:"cluster"`
	Environment    string `json:"environment"`
	Namespace      string `json:"namespace"`
	ContainerCount int    `json:"container_count"`
}

// VulnAffectedRepo is a repo where this vuln was detected, with the
// precise package + versions and the provider pointers needed to
// route the UI's repo-detail link. Contributors aren't inlined here
// — the UI fetches them lazily per repo from the existing provider
// endpoints, which already cache 24h in kv_store.
type VulnAffectedRepo struct {
	RepoID             string     `json:"repo_id"`
	RepoSlug           string     `json:"repo_slug"`
	Provider           string     `json:"provider"`
	ProviderInstanceID string     `json:"provider_instance_id"`
	Org                string     `json:"org"`
	Slug               string     `json:"slug"`
	IsPrivate          bool       `json:"is_private"`
	PkgName            string     `json:"pkg_name"`
	InstalledVersion   string     `json:"installed_version"`
	FixedVersion       string     `json:"fixed_version"`
	Source             string     `json:"source"`
	ScannedAt          *time.Time `json:"scanned_at"`
}

// VulnAffectedImage is an image digest where this vuln was found,
// with the scan provenance and the (ACL-filtered) set of running
// deployments.
type VulnAffectedImage struct {
	ImageID          string                `json:"image_id"`
	ImageSlug        string                `json:"image_slug"`
	ImageDigest      string                `json:"image_digest"`
	SourceRepoID     string                `json:"source_repo_id,omitempty"`
	VerifiedSource   bool                  `json:"verified_source"`
	PkgName          string                `json:"pkg_name"`
	InstalledVersion string                `json:"installed_version"`
	FixedVersion     string                `json:"fixed_version"`
	Source           string                `json:"source"`
	ScannedAt        *time.Time            `json:"scanned_at"`
	// Clusters is populated by attachClusterPresence after the main
	// query runs, not by the scanner — `gorm:"-"` tells GORM not to
	// treat it as a relation (which fails association-resolution on
	// the raw Scan path).
	Clusters []VulnClusterPresence `json:"clusters" gorm:"-"`
}

// VulnDetailResponse is the full payload for GET /api/vulnerabilities/{id}.
// Enrichment is nil when no external source has returned metadata yet
// (a VULN_META_FETCH job is enqueued on the spot and subsequent
// requests will include it). The view still renders — title /
// description / severity come through from the scan-side data.
type VulnDetailResponse struct {
	VulnID         string              `json:"vuln_id"`
	Title          string              `json:"title"`
	Description    string              `json:"description"`
	Severity       string              `json:"severity"`
	Sources        []string            `json:"sources"`
	Enrichment     *vulnmeta.Metadata  `json:"enrichment,omitempty"`
	EnrichmentLoading bool             `json:"enrichment_loading"`
	AffectedRepos  []VulnAffectedRepo  `json:"affected_repos"`
	AffectedImages []VulnAffectedImage `json:"affected_images"`
	RepoCount      int                 `json:"repo_count"`
	ImageCount     int                 `json:"image_count"`
}

// VulnDetailHandler — GET /api/vulnerabilities/{vuln_id}
//
// Returns the full detail view: advisory metadata (if enriched),
// affected repos (ACL-filtered) with provider pointers for
// contributor lookups, and affected images (ACL-filtered) with
// the list of clusters they're running in.
//
// Metadata freshness: cached in vuln_metadata, backfilled by the
// VULN_META_FETCH job type. If no row exists yet, we enqueue a
// fetch job and mark enrichment_loading=true so the UI can show a
// "enriching…" pill without failing the whole render.
func VulnDetailHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		vulnID := strings.TrimSpace(r.PathValue("vuln_id"))
		if vulnID == "" || vulnID == "_none" {
			http.Error(w, "missing vuln_id", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		resp := VulnDetailResponse{
			VulnID:         vulnID,
			AffectedRepos:  []VulnAffectedRepo{},
			AffectedImages: []VulnAffectedImage{},
		}

		// Enrichment: lookup or trigger async fetch. Exact ID hit
		// first; on miss, try aliases (e.g. user pasted GHSA-id,
		// we stored under CVE-id).
		meta, found, err := vulnmeta.Get(ctx, db, vulnID)
		if err != nil {
			log.Printf("vuln-detail: metadata lookup %s: %v", vulnID, err)
		}
		if !found {
			if aliased, ok, err := vulnmeta.GetByAlias(ctx, db, vulnID); err == nil && ok {
				meta = aliased
				found = true
			}
		}
		if found && meta != nil {
			resp.Enrichment = meta
			resp.Title = meta.Title
			resp.Description = meta.Description
			if meta.Severity != "" {
				resp.Severity = meta.Severity
			}
			resp.Sources = decodeStringArrayJSON(meta.Sources)
		} else {
			// Not enriched — enqueue a fetch and return whatever the
			// scan-side data gives us (see fillFromAssets below).
			jobs.EnqueueVulnMetaFetches(ctx, db, []string{vulnID})
			resp.EnrichmentLoading = true
		}

		// Asset queries run against the union of the requested vuln_id
		// plus every alias we've learned from upstream — clicking
		// "CVE-2025-49844" should surface the same images that were
		// stored under the canonical "BIT-valkey-2025-49844" advisory.
		// Scanner-stored rows carry whatever prefix the scanner chose
		// (Grype favours BIT-*, OSV emits the canonical ID); aliases
		// bridge both.
		vulnIDs := vulnmeta.AliasSet(vulnID, meta)
		osvAffected := vulnmeta.ExtractOSVAffected(meta)

		// Affected repos — scoped by ACL.
		repoClause, err := acl.ReadableRepoClause(ctx, acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		repoSQL, repoArgs := aclWhereFragment(repoClause)

		var repoRows []VulnAffectedRepo
		// repos.id is varchar(36); the view already returns repo_id as
		// text so no cast is needed on the join — casting either side
		// to uuid collides with the varchar column type.
		//
		// DISTINCT ON (v.repo_id) collapses alias duplicates. The
		// alias set expansion can return multiple rows per repo (one
		// per scanner-reported vuln_id — BIT-X, CVE-X, GHSA-X), which
		// otherwise breaks the frontend's keyed {#each} over repo_id.
		if err := db.WithContext(ctx).Raw(`
			SELECT DISTINCT ON (v.repo_id)
			       v.repo_id, v.repo_slug,
			       r.provider, r.provider_instance_id, r.org, r.slug, r.is_private,
			       v.pkg_name, v.installed_version, v.fixed_version,
			       v.source, v.scanned_at
			FROM view_unified_repositories_vulnerabilities v
			JOIN repos r ON r.id = v.repo_id
			WHERE v.vuln_id IN ? AND (`+repoSQL+`)
			ORDER BY v.repo_id, v.scanned_at DESC NULLS LAST
		`, append([]any{vulnIDs}, repoArgs...)...).Scan(&repoRows).Error; err != nil {
			log.Printf("vuln-detail: repo query %s: %v", vulnID, err)
		}
		// Override scanner-reported fix with the OSV-derived one when
		// we can compute it — grype and trivy sometimes report the
		// first range's fix (7.2.11) even when the installed version
		// is in a later range whose applicable fix is different (8.1.4).
		for i := range repoRows {
			if fix := vulnmeta.ApplicableFix(osvAffected, repoRows[i].PkgName, repoRows[i].InstalledVersion); fix != "" {
				repoRows[i].FixedVersion = fix
			}
		}
		// Preserve the empty-slice init on nil results — a nil slice
		// marshals to JSON `null`, which trips the frontend's `.length`
		// check and leaves the page stuck on its loading skeleton.
		if repoRows != nil {
			resp.AffectedRepos = repoRows
		}
		resp.RepoCount = len(resp.AffectedRepos)

		// Affected images — scoped by image ACL.
		imageClause, err := acl.ReadableImageClause(ctx, acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "d")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		imageACLSQL := "TRUE"
		var imageACLArgs []any
		if !imageClause.Unrestricted {
			if imageClause.Deny() {
				imageACLSQL = "FALSE"
			} else {
				imageACLSQL = "v.image_id IN (SELECT d.id FROM image_digests d WHERE " + imageClause.SQL + ")"
				imageACLArgs = imageClause.Args
			}
		}

		var imageRows []VulnAffectedImage
		// DISTINCT ON (image_id) collapses the row-per-finding output of
		// view_unified_image_vulnerabilities down to one row per image.
		// A single image can carry multiple findings for the same CVE
		// (re-scans, multi-matcher overlap), and the detail page wants
		// the latest per image — the most recent scanned_at wins.
		if err := db.WithContext(ctx).Raw(`
			SELECT DISTINCT ON (v.image_id)
			       v.image_id, v.image_slug, v.image_digest,
			       v.source_repo_id, v.verified_source,
			       v.pkg_name, v.installed_version, v.fixed_version,
			       v.source, v.scanned_at
			FROM view_unified_image_vulnerabilities v
			WHERE v.vuln_id IN ? AND (`+imageACLSQL+`)
			ORDER BY v.image_id, v.scanned_at DESC NULLS LAST
		`, append([]any{vulnIDs}, imageACLArgs...)...).Scan(&imageRows).Error; err != nil {
			log.Printf("vuln-detail: image query %s: %v", vulnID, err)
		}

		// Attach cluster presence per image (ACL-filtered). We batch
		// this into one query rather than N subqueries — the digest
		// list is typically <10 items.
		if len(imageRows) > 0 {
			imageRows = attachClusterPresence(ctx, r, db, imageRows)
		}
		// Same OSV-derived fix-version override as the repo branch.
		for i := range imageRows {
			if fix := vulnmeta.ApplicableFix(osvAffected, imageRows[i].PkgName, imageRows[i].InstalledVersion); fix != "" {
				imageRows[i].FixedVersion = fix
			}
		}
		if imageRows != nil {
			resp.AffectedImages = imageRows
		}
		resp.ImageCount = len(resp.AffectedImages)

		writeJSON(w, http.StatusOK, resp)
	}
}

// attachClusterPresence joins affected-image rows against cluster_record
// (kind=Container, pod_phase=Running, matching digest) and attaches the
// ACL-filtered cluster list to each image. One query over all digests;
// grouped in-memory to avoid N subqueries when an image shows up in
// many namespaces.
func attachClusterPresence(ctx context.Context, r *http.Request, db *gorm.DB, images []VulnAffectedImage) []VulnAffectedImage {
	digests := make([]string, 0, len(images))
	for _, im := range images {
		if im.ImageDigest != "" {
			digests = append(digests, im.ImageDigest)
		}
	}
	if len(digests) == 0 {
		return images
	}

	type presenceRow struct {
		Digest         string `gorm:"column:digest"`
		ClusterID      string `gorm:"column:cluster_id"`
		Cluster        string `gorm:"column:cluster"`
		Environment    string `gorm:"column:environment"`
		Namespace      string `gorm:"column:namespace"`
		ContainerCount int    `gorm:"column:container_count"`
	}
	var rows []presenceRow
	err := db.WithContext(ctx).Raw(`
		SELECT
		    cr.data->>'digest'     AS digest,
		    cr.data->>'cluster_id' AS cluster_id,
		    cr.data->>'cluster'    AS cluster,
		    cr.data->>'environment' AS environment,
		    cr.data->>'namespace'  AS namespace,
		    COUNT(DISTINCT cr.data->>'pod_uid')::int AS container_count
		FROM cluster_record cr
		WHERE cr.data->>'kind'      = 'Container'
		  AND cr.data->>'pod_phase' = 'Running'
		  AND cr.data->>'msg'       <> 'DELETE'
		  AND cr.data->>'digest'    IN ?
		GROUP BY cr.data->>'digest', cr.data->>'cluster_id',
		         cr.data->>'cluster', cr.data->>'environment',
		         cr.data->>'namespace'
		ORDER BY cluster, namespace
	`, digests).Scan(&rows).Error
	if err != nil {
		log.Printf("vuln-detail: cluster presence query: %v", err)
		return images
	}

	// Filter by cluster ACL. Rather than reach into scam (package
	// cycle risk), we do the filter in-Go against a readable-
	// cluster-IDs lookup the handler is already allowed to use.
	readableClusters, unrestrictedCluster, err := readableClusterIDSet(r, db)
	if err != nil {
		log.Printf("vuln-detail: cluster ACL: %v", err)
		return images
	}

	presenceByDigest := make(map[string][]VulnClusterPresence, len(digests))
	for _, row := range rows {
		if !unrestrictedCluster {
			if _, ok := readableClusters[row.ClusterID]; !ok {
				continue
			}
		}
		presenceByDigest[row.Digest] = append(presenceByDigest[row.Digest], VulnClusterPresence{
			ClusterID:      row.ClusterID,
			Cluster:        row.Cluster,
			Environment:    row.Environment,
			Namespace:      row.Namespace,
			ContainerCount: row.ContainerCount,
		})
	}

	for i := range images {
		images[i].Clusters = presenceByDigest[images[i].ImageDigest]
		if images[i].Clusters == nil {
			images[i].Clusters = []VulnClusterPresence{}
		}
	}
	return images
}

// decodeStringArrayJSON unmarshals a JSONB []string into a Go slice.
// Missing / malformed payload returns nil so the caller doesn't need
// error handling.
func decodeStringArrayJSON(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}
