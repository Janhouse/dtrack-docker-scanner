#!/bin/bash
set -e

echo "=== Docker SBOM Scanner ==="
echo "Dependency-Track URL: ${DTRACK_URL}"
echo "Scan interval: ${SCAN_INTERVAL:-0 */6 * * *}"

# Validate required env vars
if [[ -z "$DTRACK_URL" ]]; then
    echo "ERROR: DTRACK_URL is required"
    exit 1
fi

if [[ -z "$DTRACK_API_KEY" ]]; then
    echo "ERROR: DTRACK_API_KEY is required"
    exit 1
fi

# Test Docker socket
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to Docker socket"
    exit 1
fi

# Test Dependency-Track connection
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    "${DTRACK_URL}/api/v1/project?limit=1")

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "ERROR: Cannot connect to Dependency-Track (HTTP $HTTP_CODE)"
    exit 1
fi

echo "Connection tests passed"

# Run initial scan if requested
if [[ "${SCAN_ON_START:-true}" == "true" ]]; then
    echo "Running initial scan..."
    /app/scripts/scan.sh
fi

# Update crontab with custom schedule if provided
if [[ -n "$SCAN_INTERVAL" ]]; then
    echo "${SCAN_INTERVAL} /app/scripts/scan.sh >> /var/log/scanner.log 2>&1" > /etc/crontabs/root
fi

echo "Starting cron daemon..."
exec crond -f -l 2
