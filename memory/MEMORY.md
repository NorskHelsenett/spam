# Project Memory: SPAM Control Center

## Verification Commands
- Go: `go vet -C /home/jonasbg/Source/github/NorskHelsenett/spam/api ./...`
- Frontend: `npm run --prefix /home/jonasbg/Source/github/NorskHelsenett/spam/web check`
- Helm: `helm lint .helm/`

## Key Architecture
- `/api` — Go backend (Chi router, GORM, module: `github.com/NorskHelsenett/spam`)
- `/web` — SvelteKit frontend (Svelte 5 + Tailwind, Gruvbox dark theme)
- `/runner` — Scanner binary (separate Go module), Dockerfile for K8s jobs
- `/.helm` — Helm chart for K8s deployment

## Pre-existing Frontend Errors (ignore)
16 errors in fixtures.ts, providers/+page.svelte, providers/repo/+page.svelte,
search/+page.svelte — unrelated to new feature work.

## Patterns
- Handler signature: `func FooHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc`
- Auth check: `requireAuth(w, r, authService)` or `requireAdmin(w, r, authService)`
- JSON response: `writeJSON(w, http.StatusOK, payload)` — defined in sboms.go
- GORM AutoMigrate models in `api/cmd/server/main.go`
- SQL migrations loaded via `db.EnsureViews(...)` in main.go
