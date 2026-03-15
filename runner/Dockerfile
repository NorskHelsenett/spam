# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o runner ./cmd/main.go && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o trivy-scanner ./cmd/trivy-scanner/main.go

# Get syft binary
FROM ghcr.io/anchore/syft:latest AS syft

# Get trivy binary
FROM aquasec/trivy:latest AS trivy

# Get gitleaks binary
FROM ghcr.io/gitleaks/gitleaks:latest AS gitleaks

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache git ca-certificates

# Copy binaries from official images
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

# Copy Go binaries from builder
COPY --from=builder /build/runner /usr/local/bin/runner
COPY --from=builder /build/trivy-scanner /usr/local/bin/trivy-scanner

# Create directories for runner and trivy cache
# Make /work and /trivy-cache writable by any user for podman compatibility
RUN mkdir -p /home/runner/.cache /work /trivy-cache && \
    adduser -D -u 1000 runner && \
    chown -R 1000:1000 /home/runner && \
    chmod 777 /work /trivy-cache

USER 1000:1000
ENV HOME=/home/runner
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/runner"]
