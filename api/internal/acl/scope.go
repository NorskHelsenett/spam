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
//  1. Admins → unrestricted.
//  2. Public repos (is_private = false) are always readable.
//  3. Private repos are readable if any subject grant matches.
//
// If there are no grants and no public rule applies to the query, the
// caller should check Deny(); otherwise the OR with is_private=false
// still lets public rows through, which is the intended behavior.
func ReadableRepoClause(ctx context.Context, p Provider, subj Subject, alias string) (Clause, error) {
	if subj.IsAdmin || subj.IsGlobalReader {
		return Clause{Unrestricted: true}, nil
	}
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "repos"
	}

	patterns, err := grantsFor(ctx, p, subj, ScopeRepo)
	if err != nil {
		return Clause{}, err
	}

	grantSQL, grantArgs, allMatch := compileRepoPatterns(patterns, alias)
	if allMatch {
		return Clause{Unrestricted: true}, nil
	}

	publicSQL := fmt.Sprintf("%s.is_private = false", alias)
	if grantSQL == "" {
		// No grants: only public repos are visible.
		return Clause{SQL: publicSQL}, nil
	}
	return Clause{
		SQL:  fmt.Sprintf("(%s OR (%s))", publicSQL, grantSQL),
		Args: grantArgs,
	}, nil
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
//   - An explicit image grant matches the image identity.
//
// Unsigned images (verified_source = false) can therefore never
// piggyback on repo access — the OCI source label is advisory until
// signing lands. Images with no source_repo_id also require an
// explicit grant.
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
