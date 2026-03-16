# Multi-stage build for spam (SvelteKit static + Go server)
# 1. Frontend build stage
FROM node:22-alpine AS frontend
WORKDIR /app

# Only copy package manifests first for better layer caching
COPY web/package.json web/package-lock.json ./web/
WORKDIR /app/web
RUN npm ci --include=dev

# Copy rest of frontend source
COPY web/ .
# Build static site (outputs to web/build via adapter-static config)
RUN NODE_OPTIONS=--max-old-space-size=4096 npm run build

# 2. Go build stage
FROM golang:1.26-alpine AS gobuilder
# Cross-compilation setup
ARG TARGETOS
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH

ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /go/api/
# Enable Go modules and caching
COPY api/go.mod api/go.sum ./

# Download dependencies with verify
RUN go mod download && go mod verify

# Copy Go source
COPY api/ .
# Copy built frontend from previous stage into expected path
COPY --from=frontend /app/web/build ./web/build
# Build static binaries (CGO disabled - using pure Go PostgreSQL driver)
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -buildvcs=false \
    -ldflags='-w -s -buildid=' \
    -o /go/bin/spam ./cmd/server

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -buildvcs=false \
    -ldflags='-w -s -buildid=' \
    -o /go/bin/worker ./cmd/worker

# 3. Final runtime stage (scratch for minimal size)
FROM alpine:3.20 AS certs
# Install CA certificates (kept in its own layer so we can copy just what's needed)
RUN apk add --no-cache ca-certificates

FROM scratch AS runtime
LABEL org.opencontainers.image.source="https://github.com/NorskHelsenett/spam" \
      org.opencontainers.image.title="SPAM" \
      org.opencontainers.image.description="Software Package Assets Management" \
      org.opencontainers.image.licenses="MIT"

ENV GIN_MODE=release

WORKDIR /app

# Copy in SSL root certificates so outbound HTTPS works (Go uses these at runtime)
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Copy statically linked binaries and prerendered assets
COPY --from=gobuilder /go/bin/spam /app/spam
COPY --from=gobuilder /go/bin/worker /app/worker
COPY --from=gobuilder /go/api/web/build /app/web/build
COPY --from=gobuilder /go/api/migrations /app/migrations

EXPOSE 8080
ENV PORT=8080

# No healthcheck (scratch has no shell/tools); rely on external monitoring.
ENTRYPOINT ["/app/spam"]
