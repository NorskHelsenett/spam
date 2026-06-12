package uiapi

// DB-backed tests for the dependency CSV export queries. They run only when
// DATABASE_URL points at a disposable PostgreSQL instance (the queries need
// real Postgres features: materialized views, FULL OUTER JOIN, jsonb):
//
//	docker run -d --name spam-export-test -e POSTGRES_PASSWORD=t -p 55432:5432 postgres:16
//	DATABASE_URL="host=localhost port=55432 user=postgres password=t dbname=postgres sslmode=disable" \
//	  go test ./internal/uiapi/ -run TestDependencyExport

import (
	"context"
	"os"
	"testing"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"gorm.io/gorm"
)

type exportTestRow struct {
	Repo          string
	Version       string
	ComponentName string `gorm:"column:component_name"`
	Ecosystem     string
}

func openExportTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed export tests")
	}
	gormDB, err := db.Open(context.Background(), db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return gormDB
}

// seedExportFixtures creates two repos, one container image and one package
// universe designed to exercise every export semantics rule:
//
//   - "leftpad" npm: SBOM + manifest in repo-a, also in the image → "both"
//   - "mixed" npm: SBOM only in repo-a, manifest only in repo-b → package-
//     level "both" without any repo+version tuple present in both sources
//   - "rightpad" npm: manifest only (repo-b)
//   - "musl" apk: image-only (base-image package, no repo binding)
func seedExportFixtures(t *testing.T, gormDB *gorm.DB) {
	t.Helper()
	ctx := context.Background()

	if err := gormDB.AutoMigrate(
		&db.ViewSchemaVersion{},
		&assets.Repo{},
		&assets.RepoCommit{},
		&assets.ImageDigest{},
		&artifacts.SBOM{},
		&artifacts.SBOMBinding{},
		&manifests.Manifest{},
		&manifests.ManifestDependency{},
		&providerconfig.ProviderInstance{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := cache.EnsureTable(ctx, gormDB); err != nil {
		t.Fatalf("ensure kv_store: %v", err)
	}
	for _, table := range []string{
		"manifest_dependencies", "manifests", "sbom_bindings", "sboms",
		"image_digests", "repo_commits", "repos", "kv_store",
	} {
		if err := gormDB.Exec("TRUNCATE TABLE " + table + " CASCADE").Error; err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	if err := db.EnsureViews(ctx, gormDB,
		"../../migrations/20260204_create_materialized_view_refreshes.sql",
		"../../migrations/20260310_optimize_sbom_component_view_latest_per_repo.sql",
	); err != nil {
		t.Fatalf("ensure views: %v", err)
	}

	mustCreate := func(value interface{}) {
		t.Helper()
		if err := gormDB.Create(value).Error; err != nil {
			t.Fatalf("seed %T: %v", value, err)
		}
	}

	mustCreate(&assets.Repo{ID: "repo-a", Provider: "github", Org: "org", Slug: "app-a"})
	mustCreate(&assets.Repo{ID: "repo-b", Provider: "github", Org: "org", Slug: "app-b"})
	mustCreate(&assets.RepoCommit{ID: "rc-a", RepoID: "repo-a", CommitSHA: "abc123", AuthorEmail: "runner@nhn.no"})
	mustCreate(&assets.ImageDigest{
		ID: "img-1", Registry: "ghcr.io", Repository: "org/app-a", Digest: "sha256:111",
		SourceRepoID: "repo-a", VerifiedSource: true,
	})

	repoSBOM := []byte(`{"components":[` +
		`{"bom-ref":"a","purl":"pkg:npm/leftpad@1.0.0","name":"leftpad","version":"1.0.0"},` +
		`{"bom-ref":"b","purl":"pkg:npm/mixed@2.0.0","name":"mixed","version":"2.0.0"}]}`)
	imageSBOM := []byte(`{"components":[` +
		`{"bom-ref":"c","purl":"pkg:npm/leftpad@1.0.0","name":"leftpad","version":"1.0.0"},` +
		`{"bom-ref":"d","purl":"pkg:apk/alpine/musl@1.2.4","name":"musl","version":"1.2.4"}]}`)
	mustCreate(&artifacts.SBOM{ID: "sbom-repo", Format: "cyclonedx-json", ContentHash: []byte("h1"), ContentBytes: repoSBOM})
	mustCreate(&artifacts.SBOM{ID: "sbom-img", Format: "cyclonedx-json", ContentHash: []byte("h2"), ContentBytes: imageSBOM})
	mustCreate(&artifacts.SBOMBinding{ID: "bind-repo", AssetType: "REPO_COMMIT", AssetRefID: "rc-a", SBOMID: "sbom-repo", Source: "runner"})
	mustCreate(&artifacts.SBOMBinding{ID: "bind-img", AssetType: "IMAGE_DIGEST", AssetRefID: "img-1", SBOMID: "sbom-img", Source: "runner"})

	mustCreate(&manifests.Manifest{ID: "m-a", RepoID: "repo-a", Path: "package.json", Type: "package.json"})
	mustCreate(&manifests.ManifestDependency{ID: "md-1", ManifestID: "m-a", Name: "leftpad", Version: "1.0.0", Ecosystem: "npm", Direct: true})
	mustCreate(&manifests.Manifest{ID: "m-b", RepoID: "repo-b", Path: "package.json", Type: "package.json"})
	mustCreate(&manifests.ManifestDependency{ID: "md-2", ManifestID: "m-b", Name: "rightpad", Version: "3.0.0", Ecosystem: "npm", Direct: true})
	mustCreate(&manifests.ManifestDependency{ID: "md-3", ManifestID: "m-b", Name: "mixed", Version: "2.0.0", Ecosystem: "npm", Direct: true})

	if err := gormDB.Exec("REFRESH MATERIALIZED VIEW sbom_component_view").Error; err != nil {
		t.Fatalf("refresh sbom_component_view: %v", err)
	}

	store := cache.NewPostgresStore(gormDB)
	if err := assets.UpsertRepoCache(ctx, store, "repo-a", "", "",
		`[{"author_email":"bob@nhn.no"}]`, `[{"email":"alice@nhn.no"}]`); err != nil {
		t.Fatalf("seed repo cache: %v", err)
	}
}

func runExportQuery(t *testing.T, gormDB *gorm.DB, search, ecosystem, source string) []exportTestRow {
	t.Helper()
	parsed, err := parseDependencySearchQuery(search)
	if err != nil {
		t.Fatalf("parse search %q: %v", search, err)
	}
	query, args := buildDependencyExportQuery("TRUE", nil, parsed, search, ecosystem, "", source)
	var rows []exportTestRow
	if err := gormDB.Raw(query, args...).Scan(&rows).Error; err != nil {
		t.Fatalf("export query (source=%q): %v", source, err)
	}
	return rows
}

func rowKeys(rows []exportTestRow) map[string]bool {
	keys := make(map[string]bool, len(rows))
	for _, r := range rows {
		keys[r.Repo+" "+r.ComponentName+"@"+r.Version] = true
	}
	return keys
}

func TestDependencyExportQuery(t *testing.T) {
	gormDB := openExportTestDB(t)
	seedExportFixtures(t, gormDB)
	ctx := context.Background()

	t.Run("no filters returns full result set including image-only packages", func(t *testing.T) {
		keys := rowKeys(runExportQuery(t, gormDB, "", "", ""))
		want := []string{
			"github/org/app-a leftpad@1.0.0",
			"github/org/app-a mixed@2.0.0",
			"github/org/app-b rightpad@3.0.0",
			"github/org/app-b mixed@2.0.0",
			"ghcr.io/org/app-a leftpad@1.0.0",
			"ghcr.io/org/app-a alpine/musl@1.2.4",
		}
		for _, w := range want {
			if !keys[w] {
				t.Errorf("missing row %q (got %v)", w, keys)
			}
		}
		if len(keys) != len(want) {
			t.Errorf("expected %d rows, got %d: %v", len(want), len(keys), keys)
		}
	})

	t.Run("source=sbom keeps manifest-corroborated rows", func(t *testing.T) {
		keys := rowKeys(runExportQuery(t, gormDB, "", "", "sbom"))
		// leftpad@repo-a is in both SBOM and manifest — the old exclusive
		// filter dropped it even though the table shows it under "SBOM only".
		if !keys["github/org/app-a leftpad@1.0.0"] {
			t.Errorf("source=sbom must include SBOM rows that also have a manifest, got %v", keys)
		}
		if keys["github/org/app-b rightpad@3.0.0"] {
			t.Errorf("source=sbom must not include manifest-only rows, got %v", keys)
		}
	})

	t.Run("source=manifest", func(t *testing.T) {
		keys := rowKeys(runExportQuery(t, gormDB, "", "", "manifest"))
		for _, w := range []string{"github/org/app-a leftpad@1.0.0", "github/org/app-b rightpad@3.0.0", "github/org/app-b mixed@2.0.0"} {
			if !keys[w] {
				t.Errorf("missing manifest row %q (got %v)", w, keys)
			}
		}
		if keys["ghcr.io/org/app-a alpine/musl@1.2.4"] {
			t.Errorf("source=manifest must not include image-only rows, got %v", keys)
		}
	})

	t.Run("source=both is package-level like the list endpoint", func(t *testing.T) {
		keys := rowKeys(runExportQuery(t, gormDB, "", "", "both"))
		// "mixed" is SBOM-verified in repo-a and manifest-declared in repo-b:
		// the list shows it as "both", so the export must include it even
		// though no single repo+version tuple has both sources.
		for _, w := range []string{"github/org/app-a mixed@2.0.0", "github/org/app-b mixed@2.0.0", "github/org/app-a leftpad@1.0.0"} {
			if !keys[w] {
				t.Errorf("missing both-source row %q (got %v)", w, keys)
			}
		}
		for _, banned := range []string{"github/org/app-b rightpad@3.0.0", "ghcr.io/org/app-a alpine/musl@1.2.4"} {
			if keys[banned] {
				t.Errorf("source=both must not include single-source row %q", banned)
			}
		}
	})

	t.Run("search and ecosystem filters", func(t *testing.T) {
		keys := rowKeys(runExportQuery(t, gormDB, "left", "", ""))
		if len(keys) != 2 || !keys["github/org/app-a leftpad@1.0.0"] || !keys["ghcr.io/org/app-a leftpad@1.0.0"] {
			t.Errorf("search=left: unexpected rows %v", keys)
		}
		keys = rowKeys(runExportQuery(t, gormDB, "", "apk", ""))
		if len(keys) != 1 || !keys["ghcr.io/org/app-a alpine/musl@1.2.4"] {
			t.Errorf("ecosystem=apk: unexpected rows %v", keys)
		}
		// Structured query syntax must survive the merged_all column prefix.
		keys = rowKeys(runExportQuery(t, gormDB, "leftpad@1.0.0", "", ""))
		if len(keys) != 2 {
			t.Errorf("structured search: unexpected rows %v", keys)
		}
	})

	t.Run("full export query resolves repo_id for verified images", func(t *testing.T) {
		parsed, err := parseDependencySearchQuery("")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		query, args := buildDependencyFullExportQuery("TRUE", nil, parsed, "", "", "", "")
		type fullRow struct {
			RepoID        string `gorm:"column:repo_id"`
			Repo          string
			ComponentName string `gorm:"column:component_name"`
		}
		var rows []fullRow
		if err := gormDB.Raw(query, args...).Scan(&rows).Error; err != nil {
			t.Fatalf("full export query: %v", err)
		}
		foundImage := false
		for _, r := range rows {
			if r.Repo == "ghcr.io/org/app-a" {
				foundImage = true
				if r.RepoID != "repo-a" {
					t.Errorf("verified image row should inherit source repo_id, got %q", r.RepoID)
				}
			}
		}
		if !foundImage {
			t.Error("full export missing image rows")
		}
	})

	t.Run("contributor emails merge repo_commits and kv_store cache", func(t *testing.T) {
		emails := loadContributorEmailsByRepo(gormDB, ctx, []string{"repo-a", "repo-b"})
		if got := emails["repo-a"]; got != "alice@nhn.no;bob@nhn.no;runner@nhn.no" {
			t.Errorf("repo-a emails = %q", got)
		}
		if got := emails["repo-b"]; got != "" {
			t.Errorf("repo-b should have no emails, got %q", got)
		}
	})

	t.Run("detail export assets include repo, manifest and image usages", func(t *testing.T) {
		assetsRows, err := queryDependencyAssetsForExport(gormDB, ctx, "leftpad", "npm", nil, "")
		if err != nil {
			t.Fatalf("queryDependencyAssetsForExport: %v", err)
		}
		var haveRepoSBOM, haveManifest, haveImage bool
		for _, a := range assetsRows {
			switch {
			case a.AssetType == "IMAGE_DIGEST":
				haveImage = true
				if a.ImageRegistry != "ghcr.io" || a.ImageRepository != "org/app-a" {
					t.Errorf("image asset missing identity: %+v", a)
				}
				if a.RepoID != "repo-a" {
					t.Errorf("verified image asset should inherit source repo_id, got %q", a.RepoID)
				}
			case a.Source == "sbom":
				haveRepoSBOM = true
			case a.Source == "manifest":
				haveManifest = true
			}
		}
		if !haveRepoSBOM || !haveManifest || !haveImage {
			t.Errorf("expected sbom+manifest+image assets, got sbom=%v manifest=%v image=%v (%d rows)",
				haveRepoSBOM, haveManifest, haveImage, len(assetsRows))
		}

		// Source filter must drop manifest rows but keep image rows (images
		// are SBOM-sourced).
		sbomOnly, err := queryDependencyAssetsForExport(gormDB, ctx, "leftpad", "npm", nil, "sbom")
		if err != nil {
			t.Fatalf("queryDependencyAssetsForExport sbom: %v", err)
		}
		for _, a := range sbomOnly {
			if a.Source == "manifest" {
				t.Errorf("source=sbom returned manifest asset: %+v", a)
			}
		}
		if len(sbomOnly) != 2 {
			t.Errorf("source=sbom expected 2 assets (repo+image), got %d", len(sbomOnly))
		}
	})
}
