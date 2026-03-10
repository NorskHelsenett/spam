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

## Trivy Scanner Feature (added 2026-03-10)
- Migration: `api/migrations/20260310_create_trivy_scan_tables.sql`
- HMAC auth middleware: `api/internal/auth/hmac.go`
- Models + queue logic: `api/internal/vulnerabilities/trivy.go`
- Scanner endpoints: `api/internal/uiapi/trivy_scanner.go`
- Dashboard endpoints: `api/internal/uiapi/vuln_dashboard.go`
- Router: added `/api/trivy/next`, `/api/trivy/result/{id}`, `/api/vuln/*`
- `RouterOptions.HMACKey` sourced from `RUNNER_HMAC_KEY` env var
- Scanner binary: `runner/cmd/trivy-scanner/main.go`
- Helm CronJob: `.helm/templates/trivy-scanner-cronjob.yaml`
- Frontend: `/app/vulnerabilities` page replaces `/app/agents` SBOMs entry

## Patterns
- Handler signature: `func FooHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc`
- Auth check: `requireAuth(w, r, authService)` or `requireAdmin(w, r, authService)`
- JSON response: `writeJSON(w, http.StatusOK, payload)` — defined in sboms.go
- GORM AutoMigrate models in `api/cmd/server/main.go`
- SQL migrations loaded via `db.EnsureViews(...)` in main.go
