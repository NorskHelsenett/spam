FROM alpine:3.20

RUN apk add --no-cache git curl jq ca-certificates bash

# Install websocat for WebSocket communication
ARG WEBSOCAT_VERSION=1.13.0
RUN curl -sSfL "https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.x86_64-unknown-linux-musl" \
    -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat

# Install Trivy
ARG TRIVY_VERSION=0.58.2
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Install Syft
ARG SYFT_VERSION=1.18.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Gitleaks
ARG GITLEAKS_VERSION=8.21.2
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | \
    tar xz -C /usr/local/bin gitleaks

COPY run.sh /run.sh
RUN chmod +x /run.sh

# Create directories for runner
RUN mkdir -p /home/runner/.cache /work && chown -R 1000:1000 /home/runner /work

USER 1000:1000
ENV HOME=/home/runner
WORKDIR /work
ENTRYPOINT ["/run.sh"]
