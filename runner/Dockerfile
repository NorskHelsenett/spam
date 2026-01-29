FROM alpine:3.20

RUN apk add --no-cache git curl jq ca-certificates bash

# Detect architecture for binary downloads
ARG TARGETARCH
RUN echo "Building for architecture: $TARGETARCH"

# Install websocat for WebSocket communication
ARG WEBSOCAT_VERSION=1.13.0
RUN case "$TARGETARCH" in \
        amd64) WEBSOCAT_ARCH="x86_64-unknown-linux-musl" ;; \
        arm64) WEBSOCAT_ARCH="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.${WEBSOCAT_ARCH}" \
    -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat

# Install Trivy
ARG TRIVY_VERSION=0.58.2
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Install Syft
ARG SYFT_VERSION=1.40.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Gitleaks
ARG GITLEAKS_VERSION=8.30.0
RUN case "$TARGETARCH" in \
        amd64) GITLEAKS_ARCH="x64" ;; \
        arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" | \
    tar xzf - -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks

COPY run.sh /run.sh
RUN chmod +x /run.sh

# Create directories for runner
# Make /work writable by any user for podman compatibility
RUN mkdir -p /home/runner/.cache /work && \
    chown -R 1000:1000 /home/runner && \
    chmod 777 /work

USER 1000:1000
ENV HOME=/home/runner
WORKDIR /work
ENTRYPOINT ["/run.sh"]
