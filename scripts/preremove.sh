#!/bin/sh
# Stop the service if it's running
if systemctl is-active --quiet gentility-agent; then
    systemctl stop gentility-agent
fi
systemctl disable gentility-agent 2>/dev/null || true