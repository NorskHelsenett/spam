package scam

import "strings"

// rorMetadataDTO is the nested `ror_metadata` object SPAM emits on the
// cluster API surfaces ({slug, cluster_name, env}). Distinct from
// RorMetadata in models.go, which is the inbound agent shape decoded on
// ingest — this is the outbound wire projection.
//
// The frontend keys "did this cluster bind to ROR, or is it on env-var
// fallback?" purely on this object's presence, so every field is
// omitempty and the whole object is omitted when no ROR identifier
// resolved. Build it via newRorMetadata so that contract is applied in
// one place.
type rorMetadataDTO struct {
	Slug        string `json:"slug,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
	Env         string `json:"env,omitempty"`
}

// newRorMetadata builds the wire object from resolved ROR fields,
// returning nil (→ object omitted) when none are present.
//
// Callers resolve the three fields with a clusters-table fallback
// before calling — the clusters table is the durable ROR-binding store
// (written by upsertClusterRorBinding and the ROR sync), so it carries
// the binding even when the cluster_summary MV's ROR columns lag a
// refresh or a cluster's currently-live records dropped their
// ror_metadata. Both the list (ClusterSummaryHandler) and detail
// (ClusterDetailHandler) surfaces share this so they never disagree on
// whether a cluster shows its ROR binding.
func newRorMetadata(slug, clusterName, env string) *rorMetadataDTO {
	slug = strings.TrimSpace(slug)
	clusterName = strings.TrimSpace(clusterName)
	env = strings.TrimSpace(env)
	if slug == "" && clusterName == "" && env == "" {
		return nil
	}
	return &rorMetadataDTO{Slug: slug, ClusterName: clusterName, Env: env}
}

// deref returns the pointed-to string, or "" for a nil pointer — for
// scanning nullable ROR columns straight into newRorMetadata.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
