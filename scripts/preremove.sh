#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# Check if this is an upgrade or removal
# $1 is "upgrade" for upgrades, "remove" for removal
action="${1:-remove}"

# Save running state for postinstall to check (for upgrades)
if systemctl is-active --quiet gentility; then
    touch /var/lib/gentility-agent/.was-running
    systemctl stop gentility
fi

# Only disable on actual removal, not upgrade
if [ "$action" = "remove" ]; then
    systemctl disable gentility 2>/dev/null || true
fi