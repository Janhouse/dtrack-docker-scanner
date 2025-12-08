# Docker SBOM Scanner for Dependency-Track

A Docker container scanner that automatically generates Software Bill of Materials (SBOMs) for running containers and uploads them to [OWASP Dependency-Track](https://dependencytrack.org/) for vulnerability analysis.

## Features

- Scans all running Docker containers on startup
- Watches Docker events for new containers and scans them automatically
- Generates CycloneDX SBOMs using [Trivy](https://trivy.dev/)
- Uploads SBOMs to Dependency-Track with proper tagging
- Groups projects under a parent project by hostname
- Clones vulnerability analysis decisions when container versions change
- Automatically cleans up stale projects when containers are removed
- Marks projects as inactive when containers are stopped for extended periods
- Caches recently scanned image list to avoid redundant scans
- Configurable scan schedule via cron expression

## Quick Start

### Using Docker Compose

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your Dependency-Track credentials:
   ```bash
   DTRACK_URL=https://dependency-track.example.com
   DTRACK_API_KEY=your-api-key-here
   ```

3. Start the scanner:
   ```bash
   docker compose up -d
   ```

### Using Docker Run

```bash
docker run -d \
  --name dtrack-docker-scanner \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e DTRACK_URL=https://dependency-track.example.com \
  -e DTRACK_API_KEY=your-api-key \
  ghcr.io/janhouse/dtrack-docker-scanner:latest
```

## Configuration

All configuration is done via environment variables:

### Required

| Variable | Description |
|----------|-------------|
| `DTRACK_URL` | Dependency-Track API URL (e.g., `https://dtrack.example.com`) |
| `DTRACK_API_KEY` | API key with permissions to create/update projects and upload BOMs |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INTERVAL` | `0 */6 * * *` | Cron expression for scheduled scans |
| `SCAN_ON_START` | `true` | Run a full scan when the container starts |
| `EXCLUDE_IMAGES` | `` | Comma-separated list of image name patterns to skip |
| `DTRACK_PARENT_PROJECT` | `` | Parent project name to group all scanned containers under |
| `SCANNER_HOSTNAME` | `<container hostname>` | Hostname used for tagging projects |
| `CLEANUP_STALE` | `true` | Remove projects for containers no longer running |
| `SCAN_CONCURRENCY` | `2` | Number of concurrent SBOM uploads |
| `WATCH_DOCKER` | `true` | Watch Docker events for new containers |
| `CACHE_TTL_MINUTES` | `60` | How long to cache scanned image hashes |
| `INACTIVE_AFTER_MINUTES` | `60` | Mark project inactive after container stopped this long |
| `INITIAL_CLEANUP_DELAY_MINUTES` | `3` | Delay cleanup after initial scan to allow other containers to start |
| `TZ` | `UTC` | Timezone for cron schedule |

## How It Works

### Container Scanning

1. On startup, the scanner lists all running Docker containers
2. For each container, it generates a CycloneDX SBOM using Trivy
3. The SBOM is uploaded to Dependency-Track with tags:
   - Image base name
   - `host:<hostname>` - identifies which host the container runs on
   - `docker-scanner` - marks it as scanner-managed
   - `compose:<project>` - compose project name (if applicable)
   - `imageid:<hash>` - Docker image hash for deduplication

### Docker Event Watching

When `WATCH_DOCKER=true`, the scanner listens for Docker events:
- **Container start**: Scans new containers immediately (if not recently scanned)
- **Container stop/die**: Tracks stopped containers and marks them inactive after the configured timeout

### Project Lifecycle

- New containers create new projects in Dependency-Track
- When a container image is updated, analysis decisions are cloned from the old version
- Old versions are deleted after successful clone
- Stopped containers are marked inactive (not deleted) after the configured timeout
- Containers that restart are automatically reactivated

### Deduplication

The scanner avoids redundant scans by:
1. Checking a local cache of recently scanned image hashes
2. Querying Dependency-Track for existing projects with matching `imageid:` tags
3. Only scanning images that don't exist in either cache

## Development

### Prerequisites

- [Bun](https://bun.sh/)
- Docker

### Setup

```bash
# Install dependencies
bun install

# Run in development mode
bun run dev

# Type checking
bun run typecheck

# Linting
bun run lint
bun run lint:fix
```

### Building

```bash
# Build Docker image
docker build -t dtrack-docker-scanner .

# Or using compose
docker compose build
```

## CI/CD Workflows

This project includes Gitea Actions workflows for automated building and SBOM generation.

### Builder Workflow (`.gitea/workflows/build.yml`)

Builds and pushes the Docker image to container registries.

**Inputs:**
- `custom_tags` - Comma-separated version tags (e.g., `v1.0.0,v1.0`)
- `push_to_github` - Also push to GitHub Container Registry

**Required Repository Variables:**
- `REGISTRY_URL` - Primary container registry URL
- `REPOSITORY_IMAGE` - Full image reference (e.g., `registry.example.com/org/image:latest`)
- `GHCR_IMAGE` - GitHub Container Registry image (e.g., `ghcr.io/org/image:latest`)

**Required Secrets:**
- `REGISTRY_USERNAME` - Primary registry username
- `REGISTRY_ACCESS_TOKEN` - Primary registry password/token
- `GHCR_USERNAME` - GitHub username
- `GHCR_TOKEN` - GitHub personal access token with `write:packages` scope

### SBOM Workflow (`.gitea/workflows/sbom.yml`)

Generates SBOM for the built container and uploads to Dependency-Track. Runs automatically after successful builds.

**Inputs:**
- `include_github` - Also upload SBOM for `github-latest` version
- `custom_tags` - Comma-separated version tags to upload SBOMs for

**Required Secrets:**
- `ACTIONS_GITEA_TOKEN` - Token for downloading artifacts between workflows
- `DEPENDENCY_TRACK_URL` - Dependency-Track API URL
- `DEPENDENCY_TRACK_API_KEY` - Dependency-Track API key
- `DEPENDENCY_TRACK_PROJECT_NAME` - Project name in Dependency-Track

### Checks Workflow (`.gitea/workflows/checks.yml`)

Runs linting and type checking on pull requests and pushes.

## Dependency-Track API Permissions

The API key needs the following permissions:
- `BOM_UPLOAD` - Upload SBOMs
- `PROJECT_CREATION_UPLOAD` - Auto-create projects
- `VIEW_PORTFOLIO` - List and search projects
- `PORTFOLIO_MANAGEMENT` - Update project properties, delete projects

## License

AGPL-3.0
