package acl

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTestDB connects to the dev Postgres used by the running API.
// Tests that need a live DB skip silently when the DSN env var isn't
// set so `go test ./...` stays green on machines without a Postgres.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("SPAM_TEST_DSN")
	if dsn == "" {
		t.Skip("SPAM_TEST_DSN not set; skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

// TestApplyIngestDefaults_EndToEnd writes a provider row with
// default_grants, then calls ApplyIngestDefaults and asserts that the
// expected acl_grants rows land.
//
// Runs against the real dev DB via SPAM_TEST_DSN so GORM + Postgres
// + the ux_acl_grant_identity unique index are all in the loop.
func TestApplyIngestDefaults_EndToEnd(t *testing.T) {
	db := openTestDB(t)

	// provider_instances.id is varchar(36), so UUIDs only. Owner/slug
	// are text and can carry a test tag for debuggability.
	providerID := uuid.NewString()
	testOwner := "acl-test-owner-" + providerID[:8]
	testSlug := "acl-test-slug-" + providerID[:8]

	t.Cleanup(func() {
		db.Exec(`DELETE FROM acl_grants WHERE scope_pattern->>'provider_instance_id' = ?`, providerID)
		db.Exec(`DELETE FROM provider_instances WHERE id = ?`, providerID)
	})

	defaults, _ := json.Marshal([]DefaultGrantSubject{
		{SubjectType: "group", SubjectID: "acl-test-team"},
		{SubjectType: "user", SubjectID: "acl-test-user-id"},
		{SubjectType: "", SubjectID: "skipped-because-empty-type"},
	})

	if err := db.Exec(`
		INSERT INTO provider_instances (id, type, base_url, owner_path, display_name, enabled, default_grants)
		VALUES (?, 'github', 'http://example.invalid', ?, 'acl-test', true, ?::jsonb)
		ON CONFLICT (id) DO UPDATE SET default_grants = EXCLUDED.default_grants
	`, providerID, providerID, datatypes.JSON(defaults)).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	ApplyIngestDefaults(context.Background(), db, providerID, RepoIdentity{
		Provider:           "github",
		ProviderInstanceID: providerID,
		Owner:              testOwner,
		Slug:               testSlug,
	})

	var rows []Grant
	if err := db.Where("scope_pattern->>'provider_instance_id' = ?", providerID).Find(&rows).Error; err != nil {
		t.Fatalf("read grants: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 grants (group + user, empty-type skipped), got %d", len(rows))
	}
	for _, g := range rows {
		if g.Source != SourceIngestDefault {
			t.Errorf("grant %s has source=%s, want ingest_default", g.ID, g.Source)
		}
		if g.ScopeType != ScopeRepo {
			t.Errorf("grant %s scope_type=%s, want repo", g.ID, g.ScopeType)
		}
		if g.Action != ActionRead {
			t.Errorf("grant %s action=%s, want read", g.ID, g.Action)
		}
		var pat ScopePattern
		if err := json.Unmarshal(g.ScopePattern, &pat); err != nil {
			t.Fatalf("decode pattern: %v", err)
		}
		if pat.Provider != "github" || pat.Owner != testOwner || pat.Slug != testSlug {
			t.Errorf("grant %s pattern = %+v, want github/%s/%s", g.ID, pat, testOwner, testSlug)
		}
	}

	// Re-applying must not duplicate rows — the unique index swallows
	// collisions and logs a warning rather than failing upstream.
	ApplyIngestDefaults(context.Background(), db, providerID, RepoIdentity{
		Provider:           "github",
		ProviderInstanceID: providerID,
		Owner:              testOwner,
		Slug:               testSlug,
	})
	var after int64
	if err := db.Model(&Grant{}).Where("scope_pattern->>'provider_instance_id' = ?", providerID).Count(&after).Error; err != nil {
		t.Fatalf("recount: %v", err)
	}
	if after != 2 {
		t.Fatalf("re-apply created duplicates: count=%d, want 2", after)
	}
}
