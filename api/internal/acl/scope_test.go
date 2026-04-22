package acl

import (
	"context"
	"strings"
	"testing"
)

// stubProvider feeds fixed grants to the scope helpers without
// touching the database.
type stubProvider struct {
	grants map[string][]ScopePattern
	err    error
}

func (s *stubProvider) Grants(ctx context.Context, subj Subject, scopeType string) ([]ScopePattern, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.grants[scopeType], nil
}

func TestCompileRepoPatterns_Wildcard(t *testing.T) {
	_, _, allMatch := compileRepoPatterns([]ScopePattern{{}}, "repos")
	if !allMatch {
		t.Fatalf("empty pattern must compile to unrestricted match")
	}
}

func TestCompileRepoPatterns_OwnerPrefix(t *testing.T) {
	sql, args, allMatch := compileRepoPatterns([]ScopePattern{
		{Provider: "github", Owner: "me"},
	}, "r")
	if allMatch {
		t.Fatalf("owner prefix should not be unrestricted")
	}
	if !strings.Contains(sql, "r.provider = ?") || !strings.Contains(sql, "r.org = ?") {
		t.Fatalf("expected provider and org conditions, got %q", sql)
	}
	if strings.Contains(sql, "r.slug") {
		t.Fatalf("slug should be wildcarded when absent from pattern, got %q", sql)
	}
	if len(args) != 2 || args[0] != "github" || args[1] != "me" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestCompileRepoPatterns_ExactRepo(t *testing.T) {
	sql, args, _ := compileRepoPatterns([]ScopePattern{
		{Provider: "github", Owner: "me", Slug: "here"},
	}, "r")
	if !strings.Contains(sql, "r.slug = ?") {
		t.Fatalf("expected slug condition in %q", sql)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 bound args, got %d: %#v", len(args), args)
	}
}

func TestCompileRepoPatterns_Union(t *testing.T) {
	sql, args, allMatch := compileRepoPatterns([]ScopePattern{
		{Provider: "github", Owner: "me"},
		{Provider: "gitlab", Owner: "ops"},
	}, "r")
	if allMatch {
		t.Fatalf("two narrow patterns shouldn't be unrestricted")
	}
	if strings.Count(sql, " OR ") != 1 {
		t.Fatalf("expected exactly one OR joining patterns, got %q", sql)
	}
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d: %#v", len(args), args)
	}
}

func TestCompileRepoPatterns_EmptySlice(t *testing.T) {
	sql, args, allMatch := compileRepoPatterns(nil, "r")
	if sql != "" || allMatch || args != nil {
		t.Fatalf("no patterns must yield empty SQL, got sql=%q args=%#v allMatch=%v", sql, args, allMatch)
	}
}

func TestCompileClusterPatterns(t *testing.T) {
	sql, args, _ := compileClusterPatterns([]ScopePattern{
		{ClusterID: "prod-eu-1"},
		{ClusterID: "stage"},
	}, "c")
	if !strings.Contains(sql, "c.cluster_id = ?") {
		t.Fatalf("expected cluster_id filter, got %q", sql)
	}
	if strings.Count(sql, " OR ") != 1 {
		t.Fatalf("two patterns should OR-join, got %q", sql)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %#v", args)
	}
}

func TestReadableRepoClause_Admin(t *testing.T) {
	c, err := ReadableRepoClause(context.Background(), nil, Subject{IsAdmin: true}, "repos")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Unrestricted {
		t.Fatalf("admin subject must be unrestricted, got %#v", c)
	}
}

func TestReadableRepoClause_NoGrantsPublicOnly(t *testing.T) {
	p := &stubProvider{}
	c, err := ReadableRepoClause(context.Background(), p, Subject{UserID: "u1"}, "repos")
	if err != nil {
		t.Fatal(err)
	}
	if c.Unrestricted {
		t.Fatalf("no grants must not be unrestricted")
	}
	if c.SQL != "repos.is_private = false" {
		t.Fatalf("expected public-only clause, got %q", c.SQL)
	}
	if c.Deny() {
		t.Fatalf("no grants still allows public repos — Deny() should be false")
	}
}

func TestReadableRepoClause_WildcardGrant(t *testing.T) {
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeRepo: {{}}, // wildcard
	}}
	c, err := ReadableRepoClause(context.Background(), p, Subject{GroupSlugs: []string{"global_reader"}}, "repos")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Unrestricted {
		t.Fatalf("wildcard grant must be unrestricted, got %#v", c)
	}
}

func TestReadableRepoClause_PrefixGrantOrsWithPublic(t *testing.T) {
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeRepo: {{Provider: "github", Owner: "me"}},
	}}
	c, err := ReadableRepoClause(context.Background(), p, Subject{UserID: "u1"}, "repos")
	if err != nil {
		t.Fatal(err)
	}
	if c.Unrestricted {
		t.Fatalf("narrow grant shouldn't be unrestricted")
	}
	if !strings.Contains(c.SQL, "repos.is_private = false") {
		t.Fatalf("expected public-repo OR-in: %q", c.SQL)
	}
	if !strings.Contains(c.SQL, "repos.provider = ?") {
		t.Fatalf("expected grant fragment to remain: %q", c.SQL)
	}
	if len(c.Args) != 2 {
		t.Fatalf("expected 2 args for provider+owner grant, got %#v", c.Args)
	}
}

func TestReadableClusterClause_NoGrantsDenies(t *testing.T) {
	p := &stubProvider{}
	c, err := ReadableClusterClause(context.Background(), p, Subject{UserID: "u1"}, "clusters")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Deny() {
		t.Fatalf("no cluster grants must Deny(), got %#v", c)
	}
}

func TestReadableClusterClause_WildcardUnrestricted(t *testing.T) {
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeCluster: {{}},
	}}
	c, err := ReadableClusterClause(context.Background(), p, Subject{GroupSlugs: []string{"sre"}}, "clusters")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Unrestricted {
		t.Fatalf("wildcard cluster grant must be unrestricted, got %#v", c)
	}
}

func TestCanReadRepo_PublicAlways(t *testing.T) {
	ok, err := CanReadRepo(context.Background(), nil, Subject{UserID: "u1"}, false, ScopePattern{Provider: "github", Owner: "me", Slug: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("public repo must be readable without grants")
	}
}

func TestCanReadRepo_PrivateRequiresGrant(t *testing.T) {
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeRepo: {{Provider: "github", Owner: "me"}},
	}}
	ok, err := CanReadRepo(context.Background(), p, Subject{UserID: "u1"}, true,
		ScopePattern{Provider: "github", Owner: "me", Slug: "here"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("owner prefix grant should cover a repo inside that owner")
	}

	ok, _ = CanReadRepo(context.Background(), p, Subject{UserID: "u1"}, true,
		ScopePattern{Provider: "github", Owner: "other", Slug: "x"})
	if ok {
		t.Fatalf("repo outside owner scope must be denied")
	}
}

func TestCanReadCluster(t *testing.T) {
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeCluster: {{ClusterID: "prod"}},
	}}
	ok, _ := CanReadCluster(context.Background(), p, Subject{UserID: "u1"}, "prod")
	if !ok {
		t.Fatalf("matching cluster grant should allow")
	}
	ok, _ = CanReadCluster(context.Background(), p, Subject{UserID: "u1"}, "stage")
	if ok {
		t.Fatalf("non-matching cluster must deny")
	}
}

func TestReadableImageClause_DeniesUnsignedByDefault(t *testing.T) {
	// Subject has a repo grant but no explicit image grant. Expect
	// the resulting clause to require verified_source=true.
	p := &stubProvider{grants: map[string][]ScopePattern{
		ScopeRepo: {{Provider: "github", Owner: "me"}},
	}}
	c, err := ReadableImageClause(context.Background(), p, Subject{UserID: "u1"}, "image_digests")
	if err != nil {
		t.Fatal(err)
	}
	if c.Unrestricted {
		t.Fatalf("image clause should not be unrestricted")
	}
	if !strings.Contains(c.SQL, "verified_source = true") {
		t.Fatalf("image clause must require verified_source=true to inherit from repos, got %q", c.SQL)
	}
}
