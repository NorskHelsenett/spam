// Package imagescan defines the pluggable scanner interface used by the
// image-scan runner. Each scanner implements one Category (vuln, sbom,
// secrets, signature, labels) and writes its result to a file under a
// per-scan workdir. Plugins are registered at runner startup; the API only
// passes scanner names through the job payload.
package imagescan

import (
	"context"
	"fmt"
	"sync"
)

// Category identifies what a scanner produces.
type Category string

const (
	CategoryVuln      Category = "vuln"
	CategorySBOM      Category = "sbom"
	CategorySecrets   Category = "secrets"
	CategorySignature Category = "signature"
	CategoryLabels    Category = "labels"
)

// DefaultScanner returns the default scanner name for a category.
func DefaultScanner(c Category) string {
	switch c {
	case CategoryVuln:
		return "grype"
	case CategorySBOM:
		return "syft"
	case CategorySecrets:
		return "betterleaks"
	case CategorySignature:
		return "cosign"
	case CategoryLabels:
		return "crane"
	default:
		return ""
	}
}

// ImageRef addresses an image by immutable digest.
type ImageRef struct {
	Registry   string
	Repository string
	Digest     string // "sha256:..."
}

// String returns the canonical OCI reference ("registry/repo@digest").
func (r ImageRef) String() string {
	return fmt.Sprintf("%s/%s@%s", r.Registry, r.Repository, r.Digest)
}

// Scanner is the runner-side plugin contract. Implementations shell out to a
// binary (grype, syft, cosign, ...) or call a library in-process, and write
// their raw output to workdir. The returned path is what the runner uploads
// to the API as the artifact for this category.
type Scanner interface {
	Name() string
	Category() Category
	Run(ctx context.Context, ref ImageRef, workdir string) (artifactPath string, err error)
}

var (
	registryMu sync.RWMutex
	scanners   = map[Category]map[string]Scanner{}
)

// Register makes a scanner discoverable by Resolve. Typical usage is an
// init() in each scanner's implementation file.
func Register(s Scanner) {
	registryMu.Lock()
	defer registryMu.Unlock()
	byName, ok := scanners[s.Category()]
	if !ok {
		byName = map[string]Scanner{}
		scanners[s.Category()] = byName
	}
	byName[s.Name()] = s
}

// Resolve looks up a scanner by category and name. An empty name selects the
// default scanner for the category.
func Resolve(cat Category, name string) (Scanner, bool) {
	if name == "" {
		name = DefaultScanner(cat)
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	byName, ok := scanners[cat]
	if !ok {
		return nil, false
	}
	s, ok := byName[name]
	return s, ok
}

// Registered returns the names of registered scanners for a category, sorted
// is not guaranteed. Intended for debug / admin endpoints.
func Registered(cat Category) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	byName, ok := scanners[cat]
	if !ok {
		return nil
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	return names
}
