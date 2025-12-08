#!/bin/bash
set -eE

DTRACK_URL="${DTRACK_URL}"
DTRACK_API_KEY="${DTRACK_API_KEY}"
# Trim whitespace from parent project (empty means no parent)
PARENT_PROJECT="${DTRACK_PARENT_PROJECT:-}"
PARENT_PROJECT="${PARENT_PROJECT#"${PARENT_PROJECT%%[![:space:]]*}"}"
PARENT_PROJECT="${PARENT_PROJECT%"${PARENT_PROJECT##*[![:space:]]}"}"
EXCLUDE_IMAGES="${EXCLUDE_IMAGES:-}"
SCANNER_HOSTNAME="${SCANNER_HOSTNAME:-$(hostname)}"
CLEANUP_STALE="${CLEANUP_STALE:-true}"
PROJECT_PREFIX="${PROJECT_PREFIX:-zzz-docker/}"

# Track uploaded versions for cleanup
declare -A UPLOADED_VERSIONS

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Trap errors for debugging
trap 'log "Error on line $LINENO (exit code: $?)"' ERR

# Ensure parent project exists, create if not
ensure_parent_project() {
    if [[ -z "$PARENT_PROJECT" ]]; then
        return 0
    fi

    log "Checking if parent project exists: $PARENT_PROJECT"

    # Look up parent project by name
    local encoded_name=$(printf '%s' "$PARENT_PROJECT" | jq -sRr @uri)
    local response=$(curl -s -w "\n%{http_code}" \
        "${DTRACK_URL}/api/v1/project/lookup?name=${encoded_name}&version=" \
        -H "X-Api-Key: ${DTRACK_API_KEY}" \
        -H "Accept: application/json")

    local http_code=$(echo "$response" | tail -n1)

    if [[ "$http_code" == "200" ]]; then
        log "✓ Parent project exists"
        return 0
    fi

    # Project doesn't exist, create it
    log "Creating parent project: $PARENT_PROJECT"

    local payload=$(jq -n \
        --arg name "$PARENT_PROJECT" \
        --arg hostname "$SCANNER_HOSTNAME" \
        '{
            name: $name,
            version: "",
            description: "Auto-created parent project for docker-scanner",
            tags: [
                {name: "docker-scanner"},
                {name: ("host:" + $hostname)}
            ]
        }')

    response=$(curl -s -w "\n%{http_code}" -X PUT \
        "${DTRACK_URL}/api/v1/project" \
        -H "X-Api-Key: ${DTRACK_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$payload")

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "201" ]]; then
        log "✓ Parent project created successfully"
        return 0
    elif [[ "$http_code" == "409" ]]; then
        # Already exists - that's fine
        log "✓ Parent project already exists"
        return 0
    else
        log "✗ Failed to create parent project (HTTP $http_code): $body"
        return 1
    fi
}

# Get all projects from Dependency-Track
get_all_projects() {
    local offset=0
    local limit=100
    local all_projects="[]"

    while true; do
        local response=$(curl -s -w "\n%{http_code}" \
            "${DTRACK_URL}/api/v1/project?limit=${limit}&offset=${offset}" \
            -H "X-Api-Key: ${DTRACK_API_KEY}" \
            -H "Accept: application/json")

        local http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | sed '$d')

        if [[ "$http_code" != "200" ]]; then
            log "✗ Failed to fetch projects (HTTP $http_code)"
            echo "[]"
            return 1
        fi

        local count=$(echo "$body" | jq 'length')
        if [[ "$count" -eq 0 ]]; then
            break
        fi

        all_projects=$(echo "$all_projects $body" | jq -s 'add')
        offset=$((offset + limit))

        # Safety limit
        if [[ $offset -gt 10000 ]]; then
            break
        fi
    done

    echo "$all_projects"
}

# Delete a project version from Dependency-Track
delete_project() {
    local uuid="$1"
    local name="$2"
    local version="$3"

    log "Deleting stale project: ${name}:${version}"

    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        "${DTRACK_URL}/api/v1/project/${uuid}" \
        -H "X-Api-Key: ${DTRACK_API_KEY}")

    if [[ "$http_code" == "204" ]]; then
        log "✓ Deleted successfully"
        return 0
    else
        log "✗ Delete failed (HTTP $http_code)"
        return 1
    fi
}

# Clean up stale versions for this host
cleanup_stale_projects() {
    log "=== Cleaning up stale projects for host: ${SCANNER_HOSTNAME} ==="

    local projects=$(get_all_projects)
    if [[ "$projects" == "[]" ]]; then
        log "No projects found or failed to fetch"
        return
    fi

    local deleted=0
    local kept=0

    # Filter projects matching our prefix and exact version pattern (latest@hostname)
    local our_version="latest@${SCANNER_HOSTNAME}"
    local our_projects=$(echo "$projects" | jq -r \
        --arg prefix "$PROJECT_PREFIX" \
        --arg version "$our_version" \
        '.[] | select(
            .name != null and
            .version != null and
            (.name | startswith($prefix)) and
            (.version == $version)
        ) | @base64')

    for project_b64 in $our_projects; do
        local project=$(echo "$project_b64" | base64 -d)
        local uuid=$(echo "$project" | jq -r '.uuid')
        local name=$(echo "$project" | jq -r '.name')
        local version=$(echo "$project" | jq -r '.version')

        # Build lookup key (same as what we track during upload)
        local lookup_key="${name}:${version}"

        if [[ -z "${UPLOADED_VERSIONS[$lookup_key]}" ]]; then
            # This version wasn't uploaded in current scan - it's stale
            if delete_project "$uuid" "$name" "$version"; then
                ((deleted++)) || true
            fi
        else
            ((kept++)) || true
        fi
    done

    log "Cleanup complete: $deleted deleted, $kept kept"
}

upload_sbom() {
    local image="$1"
    local sbom_file="$2"
    local compose_projects="$3"  # Comma-separated list of compose projects

    # Parse image name (ignore tag - we use fixed version per host)
    local image_name="${image%%:*}"
    local image_tag="${image##*:}"
    if [[ "$image_name" == "$image_tag" ]]; then
        image_tag="latest"
    fi

    # Extract base name without registry for tagging (e.g., nginx from registry.example.com/nginx)
    local base_name="${image_name##*/}"

    # Add prefix to project name for sorting
    local project_name="${PROJECT_PREFIX}${image_name}"

    # Use fixed version per host - this ensures we update the same project
    # entry when the container image changes, rather than creating new versions
    local project_version="latest@${SCANNER_HOSTNAME}"

    log "Uploading SBOM for ${project_name}:${project_version} (image tag: ${image_tag}, compose: ${compose_projects:-none})"

    # Create temp files (BusyBox-compatible mktemp)
    local payload_file=$(mktemp -p /tmp payload-XXXXXX)
    local sbom_b64_file=$(mktemp -p /tmp sbom-b64-XXXXXX)
    trap "rm -f '$payload_file' '$sbom_b64_file'" RETURN

    # Base64 encode the SBOM to a file (avoid command line length limits)
    base64 -w0 < "$sbom_file" > "$sbom_b64_file"

    # Build tags array: base image name, hostname, image tag, compose projects, scanner identifier
    # Use --rawfile to read large base64 content from file instead of --arg
    jq -n \
        --arg name "$project_name" \
        --arg version "$project_version" \
        --rawfile bom "$sbom_b64_file" \
        --arg parent "$PARENT_PROJECT" \
        --arg base_name "$base_name" \
        --arg hostname "$SCANNER_HOSTNAME" \
        --arg image_tag "$image_tag" \
        --arg compose "$compose_projects" \
        '{
            projectName: $name,
            projectVersion: $version,
            autoCreate: true,
            bom: ($bom | rtrimstr("\n")),
            projectTags: (
                [
                    $base_name,
                    ("host:" + $hostname),
                    ("tag:" + $image_tag),
                    "docker-scanner"
                ] + (
                    if $compose != "" then
                        ($compose | split(",") | map("compose:" + .))
                    else
                        []
                    end
                )
            )
        } + (if $parent != "" then {parentName: $parent} else {} end)' > "$payload_file"

    # Upload to Dependency-Track using file reference for large payloads
    local response=$(curl -s -w "\n%{http_code}" -X PUT \
        "${DTRACK_URL}/api/v1/bom" \
        -H "X-Api-Key: ${DTRACK_API_KEY}" \
        -H "Content-Type: application/json" \
        -d @"$payload_file")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "200" ]]; then
        local token=$(echo "$body" | jq -r '.token // empty')
        log "✓ Uploaded successfully (token: ${token:-n/a})"

        # Track this upload for cleanup phase
        UPLOADED_VERSIONS["${project_name}:${project_version}"]=1

        return 0
    else
        log "✗ Upload failed (HTTP $http_code): $body"
        return 1
    fi
}

is_excluded() {
    local image="$1"

    if [[ -z "$EXCLUDE_IMAGES" ]]; then
        return 1
    fi

    IFS=',' read -ra EXCLUDES <<< "$EXCLUDE_IMAGES"
    for pattern in "${EXCLUDES[@]}"; do
        if [[ "$image" == *"$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

main() {
    log "=== Starting SBOM scan ==="
    log "Host: ${SCANNER_HOSTNAME}"
    log "Project prefix: ${PROJECT_PREFIX}"
    log "Parent project: ${PARENT_PROJECT:-<none>}"
    log "Cleanup stale: ${CLEANUP_STALE}"

    # Ensure parent project exists (creates if needed)
    if ! ensure_parent_project; then
        log "✗ Failed to ensure parent project exists, aborting"
        exit 1
    fi

    # Get unique images from running containers with their compose projects
    # Format: image|compose_project (compose_project may be empty)
    declare -A image_compose_map
    while IFS='|' read -r img compose_proj; do
        if [[ -n "$img" ]]; then
            if [[ -n "${image_compose_map[$img]}" ]]; then
                # Append compose project if not already in list
                if [[ -n "$compose_proj" && "${image_compose_map[$img]}" != *"$compose_proj"* ]]; then
                    image_compose_map[$img]="${image_compose_map[$img]},$compose_proj"
                fi
            else
                image_compose_map[$img]="$compose_proj"
            fi
        fi
    done < <(docker ps --format '{{.Image}}|{{.Label "com.docker.compose.project"}}')

    if [[ ${#image_compose_map[@]} -eq 0 ]]; then
        log "No running containers found"

        # Still run cleanup if enabled (removes all projects for this host)
        if [[ "$CLEANUP_STALE" == "true" ]]; then
            cleanup_stale_projects
        fi
        exit 0
    fi

    local total=0
    local success=0
    local failed=0
    local skipped=0

    for image in "${!image_compose_map[@]}"; do
        local compose_projects="${image_compose_map[$image]}"
        ((total++)) || true

        # Check exclusions
        if is_excluded "$image"; then
            log "Skipping excluded image: $image"
            ((skipped++)) || true
            continue
        fi

        log "Scanning: $image"

        # Generate SBOM with Trivy (CycloneDX format) to temp file
        local sbom_file=$(mktemp -p /tmp sbom-XXXXXX)

        if ! trivy image --format cyclonedx --output "$sbom_file" "$image" 2>/dev/null; then
            log "✗ Failed to generate SBOM for $image"
            rm -f "$sbom_file"
            ((failed++)) || true
            continue
        fi

        # Clean up SBOM to fix schema validation issues with licenses
        # Remove invalid license entries that cause Dependency-Track to reject the SBOM
        local clean_sbom=$(mktemp -p /tmp sbom-clean-XXXXXX)
        jq '
            # Fix components with invalid licenses - convert to simple expression or remove
            .components = (.components // [] | map(
                if .licenses then
                    # Try to extract a valid license expression, or remove licenses entirely
                    .licenses = [.licenses[0] | if .expression then {expression} elif .license.id then {expression: .license.id} else {expression: "NOASSERTION"} end]
                else
                    .
                end
            ))
        ' "$sbom_file" > "$clean_sbom" 2>/dev/null && mv "$clean_sbom" "$sbom_file" || rm -f "$clean_sbom"

        # Verify SBOM was generated
        if [[ ! -s "$sbom_file" ]]; then
            log "✗ Empty SBOM generated for $image"
            rm -f "$sbom_file"
            ((failed++)) || true
            continue
        fi

        # Upload to Dependency-Track
        if upload_sbom "$image" "$sbom_file" "$compose_projects"; then
            ((success++)) || true
        else
            ((failed++)) || true
        fi

        # Cleanup temp file
        rm -f "$sbom_file"

        # Small delay to avoid hammering the API
        sleep 1

    done

    log "=== Scan complete ==="
    log "Total: $total | Success: $success | Failed: $failed | Skipped: $skipped"

    # Cleanup stale projects for this host
    if [[ "$CLEANUP_STALE" == "true" ]]; then
        cleanup_stale_projects
    fi
}

main "$@"
