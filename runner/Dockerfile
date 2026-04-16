# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o runner ./cmd/main.go

# Get syft binary (pinned digest for reproducibility)
FROM ghcr.io/anchore/syft:v1.42.3@sha256:5999d209a342e55e9edf70bf8930fb5b86d8f2a783fa401178372c50e21b1d36 AS syft

# Get trivy binary (pinned digest for reproducibility)
FROM aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c AS trivy

# Get betterleaks binary (pinned digest for reproducibility)
FROM ghcr.io/betterleaks/betterleaks:v1.1.1@sha256:8c1fdaaeef493bb27dda66051a2bf7874e5c6feeb5fe8eced1359afdbf8c2571 AS betterleaks

# Get grype binary (image-scan: vulnerability scanner)
FROM anchore/grype:v0.100.0 AS grype

# Get crane binary (image-scan: OCI registry client for export/config/labels)
FROM gcr.io/go-containerregistry/crane:v0.20.7 AS crane

# Get cosign binary (image-scan: signature verification)
FROM gcr.io/projectsigstore/cosign:v2.6.2 AS cosign

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache git ca-certificates tar

# Copy binaries from official images
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=betterleaks /usr/bin/betterleaks /usr/local/bin/betterleaks
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=crane /ko-app/crane /usr/local/bin/crane
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

# Copy Go binaries from builder
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
