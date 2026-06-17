package acl

import (
	"context"
	"fmt"
	"strings"
)

// Clause is a SQL fragment with its bind arguments. Unrestricted=true
// means the subject can see every row of that scope (admin, or a
// wildcard grant is in play) and callers should skip adding the
// clause. Unrestricted=false + SQL == "1 = 0" means the subject can
// see no rows at all.
type Clause struct {
	SQL          string
	Args         []any
	Unrestricted bool
}

func (c Clause) Deny() bool {
	return !c.Unrestricted && c.SQL == "1 = 0"
}

// ReadableRepoClause builds a WHERE fragment restricting rows of the
// repos table to those readable by subj. The table alias (often
// "repos" or "r") is prepended to every column reference.
//
// Rules, in evaluation order:
//  1. Admins / global_readers → unrestricted.
//  2. Public repos (is_private = false) are always readable.
//  3. Private repos are readable if any subject grant matches.
//  4. Cluster-image bridge: if a verified image running in one of
//     the subject's granted clusters has source_repo_id = R, then
//     repo R is readable. This is the OCI-label trust path — a
//     cluster operator who runs a signed image transitively gets
//     read access to its source repo.
//
// If there are no grants the public-only rule still lets public rows
// through, which is the intended behavior for discovery surfaces.
// Security / dashboard handlers that must NOT leak the existence of
// random public repos to a cluster-only operator should call
// ReadableRepoClauseStrict instead.
func ReadableRepoClause(ctx context.Context, p Provider, subj Subject, alias string) (Clause, error) {
	if subj.IsAdmin || subj.IsGlobalReader {
		return Clause{Unrestricted: true}, nil
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "repos"
	}

	grantSQL, grantArgs, allMatch, bridgeSQL, bridgeArgs, err := repoClauseParts(ctx, p, subj, alias)
	if err != nil {
		return Clause{}, err
	}
	if allMatch {
		return Clause{Unrestricted: true}, nil
	}

	publicSQL := fmt.Sprintf("%s.is_private = false", alias)
	parts := []string{publicSQL}
	var args []any
	if grantSQL != "" {
		parts = append(parts, "("+grantSQL+")")
		args = append(args, grantArgs...)
	}
	if bridgeSQL != "" {
		parts = append(parts, "("+bridgeSQL+")")
		args = append(args, bridgeArgs...)
	}
	if len(parts) == 1 {
		return Clause{SQL: publicSQL}, nil
	}
	return Clause{
		SQL:  "(" + strings.Join(parts, " OR ") + ")",
		Args: args,
	}, nil
}

// ReadableRepoClauseStrict is like ReadableRepoClause but drops the
// "public repos are readable by everyone" fallback. Use it in
// security / dashboard contexts where a caller whose only ACL entry
// point is a cluster grant must not also see random public repos.
//
// Branches preserved: admin / global_reader unrestricted, explicit
// repo grants, and the cluster-image bridge (so an operator with
// cluster grants still sees the verified source repos of images
// running in those clusters — i.e. the OCI-label binding).
//
// Subjects with none of the above get Deny.
func ReadableRepoClauseStrict(ctx context.Context, p Provider, subj Subject, alias string) (Clause, error) {
	if subj.IsAdmin || subj.IsGlobalReader {
		return Clause{Unrestricted: true}, nil
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "repos"
	}

	grantSQL, grantArgs, allMatch, bridgeSQL, bridgeArgs, err := repoClauseParts(ctx, p, subj, alias)
	if err != nil {
		return Clause{}, err
	}
	if allMatch {
		return Clause{Unrestricted: true}, nil
	}

	var parts []string
	var args []any
	if grantSQL != "" {
		parts = append(parts, "("+grantSQL+")")
		args = append(args, grantArgs...)
	}
	if bridgeSQL != "" {
		parts = append(parts, "("+bridgeSQL+")")
		args = append(args, bridgeArgs...)
	}
	if len(parts) == 0 {
		return Clause{SQL: "1 = 0"}, nil
	}
	return Clause{
		SQL:  strings.Join(parts, " OR "),
		Args: args,
	}, nil
}

// repoClauseParts is the DRY core shared by both ReadableRepoClause
// variants. Resolves explicit repo grants and the cluster→repo
// bridge once so the two callers only differ on whether they OR in
// the public-repo fallback.
//
// Returns: grantSQL/Args for explicit repo grants, allMatch=true if
// any wildcard repo grant collapses both branches to unrestricted,
// bridgeSQL/Args for the cluster→verified-image→source-repo path.
func repoClauseParts(ctx context.Context, p Provider, subj Subject, alias string) (string, []any, bool, string, []any, error) {
	patterns, err := grantsFor(ctx, p, subj, ScopeRepo)
	if err != nil {
		return "", nil, false, "", nil, err
	}
	grantSQL, grantArgs, allMatch := compileRepoPatterns(patterns, alias)
	if allMatch {
		return "", nil, true, "", nil, nil
	}

	clusterPatterns, err := grantsFor(ctx, p, subj, ScopeCluster)
	if err != nil {
		return "", nil, false, "", nil, err
	}
	bridgeSQL, bridgeArgs := compileClusterRepoBridge(clusterPatterns, alias)
	return grantSQL, grantArgs, false, bridgeSQL, bridgeArgs, nil
}

// compileClusterRepoBridge expands a subject's cluster grants into a
// repo-side predicate via the OCI label binding: an image running
// in one of the granted clusters that carries a verified source
// repo grants transitive read access to that repo. Pulled out so
// every clause that gates on repos (ReadableRepoClause, its strict
// variant, future per-resource checks) reuses the same SQL shape
// instead of redoing the join.
//
// Empty return = no bridge contribution; caller should append
// nothing. Wildcard cluster grant opens the bridge to every
// verified image running anywhere in the fleet — same semantic
// as ReadableImageClause's cluster-image inheritance branch.
//
// raw_registry (not the COALESCE'd "Docker Hub" label) is the join
// key into image_digests.registry, matching the convention used in
// scam's image queries.
func compileClusterRepoBridge(patterns []ScopePattern, alias string) (string, []any) {
	if len(patterns) == 0 {
		return "", nil
	}
	wildcard := false
	var ids []string
	for _, p := range patterns {
		if p.IsWildcard() {
			wildcard = true
			break
		}
		if p.ClusterID != "" {
			ids = append(ids, p.ClusterID)
		}
	}
	if !wildcard && len(ids) == 0 {
		return "", nil
	}
	join := "JOIN cluster_image_inventory cii " +
		"ON cii.raw_registry = d.registry " +
		"AND cii.image = d.repository " +
		"AND cii.digest = d.digest"
	if wildcard {
		return fmt.Sprintf(
			"%s.id IN (SELECT DISTINCT d.source_repo_id FROM image_digests d %s "+
				"WHERE d.verified_source = true AND d.source_repo_id <> '')",
			alias, join,
		), nil
	}
	resolveSQL, resolveArgs := clusterGrantResolveSQL(ids)
	return fmt.Sprintf(
		"%s.id IN (SELECT DISTINCT d.source_repo_id FROM image_digests d %s "+
			"WHERE d.verified_source = true AND d.source_repo_id <> '' "+
			"AND cii.cluster_id IN (%s))",
		alias, join, resolveSQL,
	), resolveArgs
}

// ReadableClusterClause builds a WHERE fragment restricting rows of
// the clusters table to those readable by subj. No public-cluster
// shortcut: clusters default to deny.
//
// If the subject has no matching grants, the returned Clause denies
// everything (SQL = "1 = 0").
func ReadableClusterClause(ctx context.Context, p Provider, subj Subject, alias string) (Clause, error) {
	if subj.IsAdmin || subj.IsGlobalReader {
		return Clause{Unrestricted: true}, nil
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "clusters"
	}

	patterns, err := grantsFor(ctx, p, subj, ScopeCluster)
	if err != nil {
		return Clause{}, err
	}

	sql, args, allMatch := compileClusterPatterns(patterns, alias)
	if allMatch {
		return Clause{Unrestricted: true}, nil
	}
	if sql == "" {
		return Clause{SQL: "1 = 0"}, nil
	}
	return Clause{SQL: sql, Args: args}, nil
}

// ReadableImageClause builds a WHERE fragment restricting rows of the
// image_digests table. Access is granted when:
//
//   - The image has a verified source (verified_source = true) AND its
//     source_repo_id is in the readable-repo set, OR
//   - An explicit image grant matches the image identity, OR
//   - The image is currently running in a cluster the subject can read
//     (looked up via cluster_image_inventory).
//
// Unsigned images (verified_source = false) can therefore never
// piggyback on repo access — the OCI source label is advisory until
// signing lands. Images with no source_repo_id also require an
// explicit grant or cluster-inheritance hit. The cluster branch is
// what gives a cluster-only user (no repo/image grants) access to
// the vuln and secret data of images running in their clusters.
func ReadableImageClause(ctx context.Context, p Provider, subj Subject, alias string) (Clause, error) {
	if subj.IsAdmin || subj.IsGlobalReader {
		return Clause{Unrestricted: true}, nil
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "image_digests"
	}

	// Explicit image grants.
	imagePatterns, err := grantsFor(ctx, p, subj, ScopeImage)
	if err != nil {
		return Clause{}, err
	}
	imageSQL, imageArgs, imageAll := compileImagePatterns(imagePatterns, alias)
	if imageAll {
		return Clause{Unrestricted: true}, nil
	}

	// Inherited-from-repo access. We compute a subquery over the repos
	// table using the same repo clause logic. source_repo_id must be
	// non-null and the image must be verified.
	repoClause, err := ReadableRepoClause(ctx, p, subj, "r")
	if err != nil {
		return Clause{}, err
	}

	// Cluster-image inheritance. Cluster grants propagate to the images
	// running in those clusters via the cluster_image_inventory MV.
	clusterPatterns, err := grantsFor(ctx, p, subj, ScopeCluster)
	if err != nil {
		return Clause{}, err
	}

	var parts []string
	var args []any
	if repoClause.Unrestricted {
		parts = append(parts, fmt.Sprintf("(%s.verified_source = true AND %s.source_repo_id <> '')", alias, alias))
	} else if !repoClause.Deny() {
		parts = append(parts,
			fmt.Sprintf("(%s.verified_source = true AND %s.source_repo_id IN (SELECT r.id FROM repos r WHERE %s))",
				alias, alias, repoClause.SQL))
		args = append(args, repoClause.Args...)
	}

	if imageSQL != "" {
		parts = append(parts, "("+imageSQL+")")
		args = append(args, imageArgs...)
	}

	nsSQL, nsArgs := hiddenNamespaceExclusion(ctx, "namespace")
	clusterImageSQL, clusterImageArgs := compileClusterImageInheritance(clusterPatterns, alias, nsSQL, nsArgs)
	if clusterImageSQL != "" {
		parts = append(parts, clusterImageSQL)
		args = append(args, clusterImageArgs...)
	}

	if len(parts) == 0 {
		return Clause{SQL: "1 = 0"}, nil
	}
	return Clause{SQL: strings.Join(parts, " OR "), Args: args}, nil
}

// CanReadRepo tests whether subj has read access to a repo identified
// by the given attributes. Intended for single-resource handlers that
// cannot benefit from a WHERE-clause scope.
func CanReadRepo(ctx context.Context, p Provider, subj Subject, isPrivate bool, attrs ScopePattern) (bool, error) {
	if subj.IsAdmin {
		return true, nil
	}
	if !isPrivate {
		return true, nil
	}
	patterns, err := grantsFor(ctx, p, subj, ScopeRepo)
	if err != nil {
		return false, err
	}
	for _, pattern := range patterns {
		if repoPatternMatches(pattern, attrs) {
			return true, nil
		}
	}
	return false, nil
}

// CanReadCluster tests whether subj has read access to the named cluster.
func CanReadCluster(ctx context.Context, p Provider, subj Subject, clusterID string) (bool, error) {
	if subj.IsAdmin {
		return true, nil
	}
	patterns, err := grantsFor(ctx, p, subj, ScopeCluster)
	if err != nil {
		return false, err
	}
	for _, pattern := range patterns {
		if pattern.IsWildcard() {
			return true, nil
		}
		if pattern.ClusterID != "" && pattern.ClusterID == clusterID {
			return true, nil
		}
	}
	return false, nil
}

// grantsFor returns the subject's grants for scopeType, or an empty
// slice if p is nil. Nil provider is a legitimate state during early
// wiring; it must not grant access but must not panic either.
func grantsFor(ctx context.Context, p Provider, subj Subject, scopeType string) ([]ScopePattern, error) {
	if p == nil {
		return nil, nil
	}
	return p.Grants(ctx, subj, scopeType)
}

// compileRepoPatterns returns (sql, args, anyWildcard). If anyWildcard
// is true the caller should treat access as unrestricted. If sql == ""
// the subject has no matching grants.
func compileRepoPatterns(patterns []ScopePattern, alias string) (string, []any, bool) {
	var parts []string
	var args []any
	for _, p := range patterns {
		if p.IsWildcard() {
			return "", nil, true
		}
		var conds []string
		if p.Provider != "" {
			conds = append(conds, fmt.Sprintf("%s.provider = ?", alias))
			args = append(args, p.Provider)
		}
		if p.ProviderInstanceID != "" {
			conds = append(conds, fmt.Sprintf("%s.provider_instance_id = ?", alias))
			args = append(args, p.ProviderInstanceID)
		}
		if p.Owner != "" {
			conds = append(conds, fmt.Sprintf("%s.org = ?", alias))
			args = append(args, p.Owner)
		}
		if p.Slug != "" {
			conds = append(conds, fmt.Sprintf("%s.slug = ?", alias))
			args = append(args, p.Slug)
		}
		if len(conds) == 0 {
			// Pattern had only non-repo fields — skip.
			continue
		}
		parts = append(parts, "("+strings.Join(conds, " AND ")+")")
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	return strings.Join(parts, " OR "), args, false
}

func compileClusterPatterns(patterns []ScopePattern, alias string) (string, []any, bool) {
	var parts []string
	var args []any
	for _, p := range patterns {
		if p.IsWildcard() {
			return "", nil, true
		}
		if p.ClusterID == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s.cluster_id = ?", alias))
		args = append(args, p.ClusterID)
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	return strings.Join(parts, " OR "), args, false
}

// clusterGrantResolveSQL returns a subquery (and its bind args) that
// translates a set of ScopeCluster grant ids into the kube cluster_id
// values used throughout the schema (cluster_image_inventory.cluster_id
// etc). Grant ids are not always kube cluster_ids: ROR keys grants by
// the cluster slug or, post identifier migration, by the ROR cluster
// UUID — neither of which equals the kube cluster_id. We resolve all
// three identifier domains against the clusters table so a
// `... IN (<clusterGrantResolveSQL>)` predicate matches regardless of
// how the grant was keyed. This mirrors scam.clusterACLFilterCol; the
// clusters table is small so the unindexed ror_slug TRIM scan is
// negligible.
func clusterGrantResolveSQL(ids []string) (string, []any) {
	return "SELECT cluster_id FROM clusters WHERE cluster_id IN ? OR (TRIM(ror_slug) <> '' AND TRIM(ror_slug) IN ?) OR (ror_cluster_uid <> '' AND ror_cluster_uid IN ?)",
		[]any{ids, ids, ids}
}

// compileClusterImageInheritance turns cluster grants into a predicate
// that matches images present in cluster_image_inventory for any of
// the readable cluster_ids. The fragment is parenthesised so the
// caller can OR it next to the image and repo branches without
// precedence surprises.
//
// Empty return ("", nil) means "no cluster-image inheritance" and the
// caller should not append anything. A wildcard cluster grant expands
// to every row in cluster_image_inventory (i.e. every image currently
// running anywhere in the fleet) — useful for a "global cluster
// reader" persona that doesn't carry global_reader.
//
// raw_registry, not the COALESCE'd `registry` column, is the join key
// into image_digests.registry — same convention the scam ImageDetail
// query uses.
//
// nsSQL/nsArgs (from hiddenNamespaceExclusion, may be empty) prune the
// inventory subquery so an image whose only running instances sit in
// admin-curated hidden namespaces doesn't inherit visibility. An image
// that also runs in one of the user's regular namespaces still matches
// through that row.
func compileClusterImageInheritance(patterns []ScopePattern, alias string, nsSQL string, nsArgs []any) (string, []any) {
	if len(patterns) == 0 {
		return "", nil
	}
	wildcard := false
	var ids []string
	for _, p := range patterns {
		if p.IsWildcard() {
			wildcard = true
			break
		}
		if p.ClusterID != "" {
			ids = append(ids, p.ClusterID)
		}
	}
	nsWhere := ""
	if nsSQL != "" {
		nsWhere = " AND " + nsSQL
	}
	if wildcard {
		return fmt.Sprintf(
			"((%s.registry, %s.repository, %s.digest) IN (SELECT raw_registry, image, digest FROM cluster_image_inventory WHERE TRUE%s))",
			alias, alias, alias, nsWhere,
		), nsArgs
	}
	if len(ids) == 0 {
		return "", nil
	}
	resolveSQL, resolveArgs := clusterGrantResolveSQL(ids)
	args := append(resolveArgs, nsArgs...)
	return fmt.Sprintf(
		"((%s.registry, %s.repository, %s.digest) IN (SELECT raw_registry, image, digest FROM cluster_image_inventory WHERE cluster_id IN (%s)%s))",
		alias, alias, alias, resolveSQL, nsWhere,
	), args
}

func compileImagePatterns(patterns []ScopePattern, alias string) (string, []any, bool) {
	var parts []string
	var args []any
	for _, p := range patterns {
		if p.IsWildcard() {
			return "", nil, true
		}
		var conds []string
		if p.Registry != "" {
			conds = append(conds, fmt.Sprintf("%s.registry = ?", alias))
			args = append(args, p.Registry)
		}
		if p.Repository != "" {
			conds = append(conds, fmt.Sprintf("%s.repository = ?", alias))
			args = append(args, p.Repository)
		}
		if p.Digest != "" {
			conds = append(conds, fmt.Sprintf("%s.digest = ?", alias))
			args = append(args, p.Digest)
		}
		if len(conds) == 0 {
			continue
		}
		parts = append(parts, "("+strings.Join(conds, " AND ")+")")
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	return strings.Join(parts, " OR "), args, false
}

func repoPatternMatches(p ScopePattern, a ScopePattern) bool {
	if p.IsWildcard() {
		return true
	}
	if p.Provider != "" && p.Provider != a.Provider {
		return false
	}
	if p.ProviderInstanceID != "" && p.ProviderInstanceID != a.ProviderInstanceID {
		return false
	}
	if p.Owner != "" && p.Owner != a.Owner {
		return false
	}
	if p.Slug != "" && p.Slug != a.Slug {
		return false
	}
	// At least one field must have constrained the match to this
	// resource — an all-empty pattern is a wildcard, handled above.
	return p.Provider != "" || p.ProviderInstanceID != "" || p.Owner != "" || p.Slug != ""
}
