#!/bin/bash

# Check if cron is running
if ! pgrep -x crond > /dev/null; then
    exit 1
fi

# Check Docker socket
if ! docker info > /dev/null 2>&1; then
    exit 1
fi

exit 0
