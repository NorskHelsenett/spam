# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o runner ./cmd/main.go

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache git ca-certificates

# Detect architecture for binary downloads
ARG TARGETARCH
RUN echo "Building for architecture: $TARGETARCH"

# Install Trivy
ARG TRIVY_VERSION=0.58.2
RUN wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Install Syft
ARG SYFT_VERSION=1.40.1
RUN wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Gitleaks
ARG GITLEAKS_VERSION=8.30.0
RUN case "$TARGETARCH" in \
        amd64) GITLEAKS_ARCH="x64" ;; \
        arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    wget -qO- "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" | \
    tar xzf - -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks

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
