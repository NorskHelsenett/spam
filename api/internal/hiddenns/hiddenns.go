// Package hiddenns holds the admin-curated list of "administrative"
// namespace patterns (nhn-scam, nhn-ror, kube-system, …) that are
// hidden from regular users' cluster views so teams see only the
// workloads they own and can fix. Admin and global_reader callers are
// never filtered — the gate lives in the callers (see
// scam.hiddenNamespaceWhere and acl.ReadableImageClause), this package
// only stores patterns and compiles them to SQL / matchers.
//
// This is a focus feature, not an access-control boundary: on a DB
// read error the helpers fail open (no filtering) so a blip never
// blanks user-facing pages.
package hiddenns

import (
	"context"
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// HiddenNamespace is one namespace pattern hidden from non-admin
// views. Pattern is either an exact namespace name or a glob with `*`
// wildcards (e.g. `nhn-*`, `kube-*`).
type HiddenNamespace struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Pattern   string    `gorm:"size:63;uniqueIndex;not null" json:"pattern"`
	Note      string    `gorm:"size:512" json:"note"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `gorm:"size:255" json:"created_by"`
}

func (HiddenNamespace) TableName() string { return "hidden_namespaces" }

// patternRe matches a Kubernetes namespace name with optional `*`
// wildcards anywhere — lowercase RFC 1123 labels plus `*`.
var patternRe = regexp.MustCompile(`^[a-z0-9*]([a-z0-9*-]*[a-z0-9*])?$`)

// ValidatePattern rejects anything that isn't a namespace-shaped glob.
// An all-wildcard pattern is refused — it would hide every namespace
// from every regular user, which is never what an admin meant.
func ValidatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("pattern is empty")
	}
	if len(p) > 63 {
		return fmt.Errorf("pattern exceeds 63 characters")
	}
	if !patternRe.MatchString(p) {
		return fmt.Errorf("pattern must be lowercase alphanumerics, '-' and '*'")
	}
	if strings.Trim(p, "*") == "" {
		return fmt.Errorf("pattern would hide every namespace")
	}
	return nil
}

// List returns all hidden-namespace rows, newest first.
func List(ctx context.Context, db *gorm.DB) ([]HiddenNamespace, error) {
	rows := []HiddenNamespace{}
	err := db.WithContext(ctx).Order("pattern ASC").Find(&rows).Error
	return rows, err
}

// Create inserts a new pattern and invalidates the pattern cache.
func Create(ctx context.Context, db *gorm.DB, pattern, note, createdBy string) (HiddenNamespace, error) {
	row := HiddenNamespace{Pattern: pattern, Note: note, CreatedBy: createdBy}
	if err := db.WithContext(ctx).Create(&row).Error; err != nil {
		return HiddenNamespace{}, err
	}
	Invalidate()
	return row, nil
}

// Delete removes a pattern by id. Returns gorm.ErrRecordNotFound when
// the id doesn't exist so the handler can answer 404.
func Delete(ctx context.Context, db *gorm.DB, id uint) error {
	res := db.WithContext(ctx).Delete(&HiddenNamespace{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	Invalidate()
	return nil
}

// Patterns returns the current pattern list through a small TTL cache —
// the exclusion rides on every hosts/images list request, and a fleet
// page burst shouldn't hammer a table that changes a few times a year.
// Multi-replica staleness is bounded by the TTL.
const patternsTTL = 30 * time.Second

var (
	cacheMu  sync.Mutex
	cached   []string
	cachedAt time.Time
)

func Patterns(ctx context.Context, db *gorm.DB) []string {
	cacheMu.Lock()
	if !cachedAt.IsZero() && time.Since(cachedAt) < patternsTTL {
		p := cached
		cacheMu.Unlock()
		return p
	}
	cacheMu.Unlock()

	var rows []string
	if err := db.WithContext(ctx).
		Raw(`SELECT pattern FROM hidden_namespaces ORDER BY pattern`).
		Scan(&rows).Error; err != nil {
		log.Printf("hiddenns: load patterns: %v", err)
		return nil // fail open — see package doc
	}
	cacheMu.Lock()
	cached, cachedAt = rows, time.Now()
	cacheMu.Unlock()
	return rows
}

// Invalidate drops the local pattern cache after a mutation.
func Invalidate() {
	cacheMu.Lock()
	cached, cachedAt = nil, time.Time{}
	cacheMu.Unlock()
}

// ExclusionSQL compiles patterns into a WHERE fragment that drops rows
// whose namespace column matches any pattern: exact patterns collapse
// into one NOT IN, globs become NOT LIKE (with %/_/\ escaped so only
// the admin's `*` acts as a wildcard). Returns ("", nil) for an empty
// pattern list.
func ExclusionSQL(col string, patterns []string) (string, []any) {
	var exact []any
	var likes []string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(p, "*") {
			likes = append(likes, globToLike(p))
		} else {
			exact = append(exact, p)
		}
	}
	var parts []string
	var args []any
	if len(exact) > 0 {
		ph := strings.TrimRight(strings.Repeat("?,", len(exact)), ",")
		parts = append(parts, col+" NOT IN ("+ph+")")
		args = append(args, exact...)
	}
	for _, lk := range likes {
		parts = append(parts, col+" NOT LIKE ?")
		args = append(args, lk)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return strings.Join(parts, " AND "), args
}

func globToLike(p string) string {
	var b strings.Builder
	for _, r := range p {
		switch r {
		case '*':
			b.WriteByte('%')
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Clause is the load-and-compile convenience used by request handlers.
func Clause(ctx context.Context, db *gorm.DB, col string) (string, []any) {
	return ExclusionSQL(col, Patterns(ctx, db))
}

// MatcherFor returns a Go-side predicate for handlers that group rows
// in memory rather than in SQL (e.g. the cluster chain view).
// ValidatePattern keeps patterns inside path.Match's safe subset, and
// namespaces contain no '/', so path.Match's `*` semantics line up
// with the SQL LIKE translation.
func MatcherFor(patterns []string) func(string) bool {
	if len(patterns) == 0 {
		return func(string) bool { return false }
	}
	return func(ns string) bool {
		for _, p := range patterns {
			if ok, err := path.Match(p, ns); err == nil && ok {
				return true
			}
		}
		return false
	}
}
