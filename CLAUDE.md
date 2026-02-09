# Claude Code Instructions

## Build & Verification Commands

When verifying code changes, use these commands instead of full builds:

### Go (API)
```bash
go vet -C /Users/jonasbg/Source/Github/spam/api ./...
```
Do NOT use `go build` - use `go vet` for verification.

### Frontend (Web)
```bash
npm run --prefix /Users/jonasbg/Source/Github/spam/web check
```
Do NOT use `npm run build` - use `npm run check` (svelte-check) for verification.

## Project Structure

- `/api` - Go backend (Chi router, GORM)
- `/web` - SvelteKit frontend (Svelte 5, Tailwind CSS)

## Code Style

- Go: Standard Go formatting (gofmt)
- TypeScript/Svelte: Prettier with Tailwind plugin
- Theme: Gruvbox dark color scheme
