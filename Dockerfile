FROM oven/bun:1-alpine AS base

# Install system dependencies
RUN apk add --no-cache \
    docker-cli \
    ca-certificates \
    tzdata \
    curl

# Install Trivy
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

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
