package scam

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TestApplySnapshotTombstones exercises the SNAPSHOT key-list path
// against a real Postgres so the GORM/pgx binding actually round-trips.
// Pure unit tests caught nothing when ANY(?::text[]) was expanding as
// a comma list — Postgres has to see the query.
//
// Skips when SPAM_TEST_DSN isn't set. Devcontainer typically exports it.
func TestApplySnapshotTombstones(t *testing.T) {
	dsn := os.Getenv("SPAM_TEST_DSN")
	if dsn == "" {
		t.Skip("SPAM_TEST_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	clusterID := "test-snapshot-" + uuid.NewString()
	now := time.Now().UTC()
	t.Cleanup(func() {
		_ = db.Exec(`DELETE FROM cluster_record WHERE data->>'cluster_id' = ?`, clusterID).Error
		_ = db.Exec(`DELETE FROM cluster_sessions WHERE cluster_id = ?`, clusterID).Error
		_ = db.Exec(`DELETE FROM clusters WHERE cluster_id = ?`, clusterID).Error
	})

	// Seed three Service rows: A and B will survive (present in
	// snapshot key list), C will be tombstoned.
	seed := func(uid string) {
		data := map[string]any{
			"cluster_id": clusterID,
			"kind":       "Service",
			"msg":        "INITIAL",
			"uid":        uid,
			"name":       "svc-" + uid,
			"namespace":  "default",
		}
		raw, _ := json.Marshal(data)
		earlier := now.Add(-time.Minute)
		if err := db.Exec(`
			INSERT INTO cluster_record (id, data, received_at, is_present, first_seen_at, last_change_at, tombstoned_at)
			VALUES (gen_random_uuid(), ?, ?, TRUE, ?, ?, NULL)
		`, datatypes.JSON(raw), earlier, earlier, earlier).Error; err != nil {
			t.Fatalf("seed %s: %v", uid, err)
		}
	}
	seed("uid-a")
	seed("uid-b")
	seed("uid-c")

	// Apply a snapshot listing only A and B as present.
	snap := Incoming{
		Msg:          "SNAPSHOT",
		Kind:         "Snapshot",
		ClusterID:    clusterID,
		SnapshotID:   "test-snapshot-id",
		TargetKind:   "Service",
		ResourceKeys: []string{"uid-a", "uid-b"},
	}
	if err := applySnapshot(context.Background(), db, snap, now); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}

	type row struct {
		UID          string
		IsPresent    bool
		TombstonedAt sql.NullTime
		LastSnap     sql.NullString
	}
	var got []row
	if err := db.Raw(`
		SELECT data->>'uid' AS uid, is_present, tombstoned_at, last_snapshot_id
		FROM cluster_record
		WHERE data->>'cluster_id' = ?
		ORDER BY data->>'uid'
	`, clusterID).Scan(&got).Error; err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d", len(got))
	}
	for _, r := range got {
		switch r.UID {
		case "uid-a", "uid-b":
			if !r.IsPresent {
				t.Errorf("%s: want is_present=true, tombstoned by snapshot", r.UID)
			}
			if r.TombstonedAt.Valid {
				t.Errorf("%s: tombstoned_at unexpectedly set: %v", r.UID, r.TombstonedAt.Time)
			}
		case "uid-c":
			if r.IsPresent {
				t.Errorf("uid-c: still present, should be tombstoned")
			}
			if !r.TombstonedAt.Valid {
				t.Errorf("uid-c: tombstoned_at not set")
			}
			if !r.LastSnap.Valid || r.LastSnap.String != "test-snapshot-id" {
				t.Errorf("uid-c: last_snapshot_id = %v, want test-snapshot-id", r.LastSnap)
			}
		default:
			t.Errorf("unexpected uid: %s", r.UID)
		}
	}
}

// TestApplySnapshotEmptyKeys verifies the degenerate case: empty key
// list means "this kind has zero rows in the cluster, tombstone
// everything". Important because if the JSON binding regresses to
// raw "{}" or similar, the query silently does nothing.
func TestApplySnapshotEmptyKeys(t *testing.T) {
	dsn := os.Getenv("SPAM_TEST_DSN")
	if dsn == "" {
		t.Skip("SPAM_TEST_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	clusterID := "test-empty-snapshot-" + uuid.NewString()
	now := time.Now().UTC()
	t.Cleanup(func() {
		_ = db.Exec(`DELETE FROM cluster_record WHERE data->>'cluster_id' = ?`, clusterID).Error
	})

	data := map[string]any{
		"cluster_id": clusterID,
		"kind":       "IngressClass",
		"msg":        "INITIAL",
		"uid":        "ic-1",
		"name":       "nginx",
	}
	raw, _ := json.Marshal(data)
	earlier := now.Add(-time.Minute)
	if err := db.Exec(`
		INSERT INTO cluster_record (id, data, received_at, is_present, first_seen_at, last_change_at, tombstoned_at)
		VALUES (gen_random_uuid(), ?, ?, TRUE, ?, ?, NULL)
	`, datatypes.JSON(raw), earlier, earlier, earlier).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	snap := Incoming{
		Msg:          "SNAPSHOT",
		Kind:         "Snapshot",
		ClusterID:    clusterID,
		TargetKind:   "IngressClass",
		ResourceKeys: nil,
	}
	if err := applySnapshot(context.Background(), db, snap, now); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}

	var isPresent bool
	if err := db.Raw(`
		SELECT is_present FROM cluster_record WHERE data->>'cluster_id' = ?
	`, clusterID).Scan(&isPresent).Error; err != nil {
		t.Fatalf("scan: %v", err)
	}
	if isPresent {
		t.Fatalf("empty snapshot should tombstone all rows for the kind")
	}
}

// TestApplySnapshotRaceProtection: a row updated AFTER the snapshot's
// reference time must not be tombstoned even if it's missing from the
// key list. This protects same-batch upserts and concurrent CREATEs.
func TestApplySnapshotRaceProtection(t *testing.T) {
	dsn := os.Getenv("SPAM_TEST_DSN")
	if dsn == "" {
		t.Skip("SPAM_TEST_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	clusterID := "test-race-" + uuid.NewString()
	snapshotRef := time.Now().UTC().Add(-time.Minute) // snapshot's "now"
	afterSnapshot := time.Now().UTC()                 // row update arrives later
	t.Cleanup(func() {
		_ = db.Exec(`DELETE FROM cluster_record WHERE data->>'cluster_id' = ?`, clusterID).Error
	})

	data, _ := json.Marshal(map[string]any{
		"cluster_id": clusterID,
		"kind":       "Service",
		"msg":        "INITIAL",
		"uid":        "fresh-uid",
		"name":       "fresh-svc",
	})
	if err := db.Exec(`
		INSERT INTO cluster_record (id, data, received_at, is_present, first_seen_at, last_change_at, tombstoned_at)
		VALUES (gen_random_uuid(), ?, ?, TRUE, ?, ?, NULL)
	`, datatypes.JSON(data), afterSnapshot, afterSnapshot, afterSnapshot).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	snap := Incoming{
		Msg:          "SNAPSHOT",
		Kind:         "Snapshot",
		ClusterID:    clusterID,
		TargetKind:   "Service",
		ResourceKeys: []string{}, // doesn't include fresh-uid
	}
	if err := applySnapshot(context.Background(), db, snap, snapshotRef); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}

	var isPresent bool
	if err := db.Raw(`
		SELECT is_present FROM cluster_record WHERE data->>'cluster_id' = ?
	`, clusterID).Scan(&isPresent).Error; err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !isPresent {
		t.Fatal("row updated after snapshot reference time should be protected from tombstone")
	}
}

