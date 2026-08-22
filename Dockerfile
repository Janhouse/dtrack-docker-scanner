FROM oven/bun:1.4-alpine AS base

# Install system dependencies
RUN apk add --no-cache \
    docker-cli \
    ca-certificates \
    tzdata \
    curl

# Install Trivy — PINNED, and the pin is load-bearing.
#
# Unpinned, this installed whatever Trivy was current at build time, and the
# CycloneDX SPEC VERSION Trivy emits is fixed by its build. Trivy 0.71 switched
# to CycloneDX 1.7, which Dependency-Track 4.14.2 rejects outright:
#     HTTP 400 {"title":"The uploaded BOM is invalid",
#               "detail":"Unrecognized specVersion 1.7"}
# So every upload silently starts failing the moment a rebuild crosses that
# boundary — the scanner keeps running, keeps generating SBOMs, and nothing
# reaches Dependency-Track.
#
# 0.70.0 is the NEWEST release still emitting CycloneDX 1.6 (verified by running
# 0.64 through 0.71 and reading the emitted specVersion), so it keeps the most
# recent vulnerability data that the server can actually accept.
#
# BUMP THIS ONLY ALONGSIDE THE SERVER: once Dependency-Track supports CycloneDX
# 1.7, move to a current Trivy. Check with
#     trivy image -q --format cyclonedx --scanners license alpine:3.19 | head -c 300
ARG TRIVY_VERSION=v0.70.0
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}" \
    && trivy --version

# Create app directory
WORKDIR /app

# Copy package files
COPY package.json bun.lockb* ./

# Install dependencies
RUN bun install --frozen-lockfile || bun install

# Copy source code
COPY tsconfig.json ./
COPY src/ ./src/

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD bun --bun run /app/src/healthcheck.ts

# Run the application
CMD ["bun", "run", "src/index.ts"]
