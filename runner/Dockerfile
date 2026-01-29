# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o runner ./cmd/main.go

# Get syft binary
FROM ghcr.io/anchore/syft:latest AS syft

# Get gitleaks binary
FROM ghcr.io/gitleaks/gitleaks:latest AS gitleaks

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache git ca-certificates

# Copy binaries from official images
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

# Copy Go binary from builder
COPY --from=builder /build/runner /usr/local/bin/runner

# Create directories for runner
# Make /work writable by any user for podman compatibility
RUN mkdir -p /home/runner/.cache /work && \
    adduser -D -u 1000 runner && \
    chown -R 1000:1000 /home/runner && \
    chmod 777 /work

USER 1000:1000
ENV HOME=/home/runner
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/runner"]
