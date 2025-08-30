#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8-8

# Stop the service if it's running
if systemctl is-active --quiet gentility-agent; then
    systemctl stop gentility-agent
fi
systemctl disable gentility-agent 2>/dev/null || true