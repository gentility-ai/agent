#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# $1 is "upgrade" during upgrades, "remove" or "purge" during removal
action="${1:-remove}"

# Reload systemd after removing service file
systemctl daemon-reload

# Only show removal message on actual removal, not upgrade
if [ "$action" = "remove" ] || [ "$action" = "purge" ]; then
    echo ""
    echo "Gentility AI Agent has been removed."
    echo "User data in /var/lib/gentility-agent and logs in /var/log/gentility-agent have been preserved."
    echo "To completely remove all data, run:"
    echo "  sudo rm -rf /var/lib/gentility-agent /var/log/gentility-agent"
    echo "  sudo userdel gentility"
    echo "  sudo groupdel gentility"
    echo ""
fi