package server

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
)

var (
	spaHandler http.Handler
	spaRootDir string
)

func init() {
	handler, root, err := newSPAHandler()
	if err != nil {
		log.Printf("spa disabled: %v", err)
		return
	}
	spaHandler = handler
	spaRootDir = root
	log.Printf("serving SPA assets from %s", spaRootDir)
}

type spaServer struct {
	fs        http.FileSystem
	indexPath string
	root      string
}

func newSPAHandler() (http.Handler, string, error) {
	rootDir, err := locateSPARoot()
	if err != nil {
		return nil, "", err
	}
	return &spaServer{
		fs:        http.Dir(rootDir),
		indexPath: "index.html",
		root:      rootDir,
	}, rootDir, nil
}

func (s *spaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") || strings.HasPrefix(r.URL.Path, "/ws") {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// allowed
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cleaned := pathpkg.Clean(r.URL.Path)
	if cleaned == "." || cleaned == "/" {
		s.serveIndex(w, r)
		return
	}
	asset := strings.TrimPrefix(cleaned, "/")
	if asset == "" {
		s.serveIndex(w, r)
		return
	}

	if handled := s.tryServeFile(w, r, asset); handled {
		return
	}

	if s.shouldFallback(r) {
		s.serveIndex(w, r)
		return
	}

	http.NotFound(w, r)
}

func (s *spaServer) tryServeFile(w http.ResponseWriter, r *http.Request, name string) bool {
	file, err := s.fs.Open(name)
	if err != nil {
		if isNotFound(err) {
			return false
		}
		log.Printf("spa: open %s: %v", filepath.Join(s.root, name), err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return true
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		log.Printf("spa: stat %s: %v", filepath.Join(s.root, name), err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return true
	}

	if info.IsDir() {
		return false
	}

	s.applyCachingHeaders(w, name)
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	return true
}

func (s *spaServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	if handled := s.tryServeFile(w, r, s.indexPath); handled {
		return
	}
	http.Error(w, "ui not available", http.StatusServiceUnavailable)
}

func (s *spaServer) shouldFallback(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.Contains(r.URL.Path, ".") {
		return false
	}
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html")
}

func (s *spaServer) applyCachingHeaders(w http.ResponseWriter, name string) {
	name = strings.ToLower(name)
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Cache-Control", "no-cache")
		return
	}
	if strings.Contains(name, ".") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
}

func locateSPARoot() (string, error) {
	candidates := collectSPACandidates()

	for _, dir := range candidates {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		index := filepath.Join(dir, "index.html")
		if stat, err := os.Stat(index); err == nil && !stat.IsDir() {
			return dir, nil
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("static assets not found; set SPA_DIST_DIR to your build output")
	}

	return "", fmt.Errorf("static assets not found; searched %s", strings.Join(candidates, ", "))
}

func collectSPACandidates() []string {
	dedup := map[string]struct{}{}
	ordered := make([]string, 0, 12)
	add := func(path string) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if _, exists := dedup[clean]; exists {
			return
		}
		dedup[clean] = struct{}{}
		ordered = append(ordered, clean)
	}

	add(os.Getenv("SPA_DIST_DIR"))
	add(os.Getenv("WEB_DIST_DIR"))

	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		add(filepath.Join(base, "web", "build"))
		add(filepath.Join(base, "..", "web", "build"))
		add(filepath.Join(base, "build"))
		add(filepath.Join(base, "static"))
	}

	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, "web", "build"))
		add(filepath.Join(wd, "build"))
		add(filepath.Join(wd, "..", "web", "build"))
		add(filepath.Join(wd, "static"))
	}

	return ordered
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}
