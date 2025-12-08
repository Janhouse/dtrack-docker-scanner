FROM alpine:3.20

# Install dependencies
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    docker-cli \
    ca-certificates \
    tzdata

# Install Trivy
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create app directory
WORKDIR /app

# Copy scripts
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Copy crontab
COPY config/crontab /etc/crontabs/root

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/scripts/healthcheck.sh

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
