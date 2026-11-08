#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# $1 is "upgrade" during upgrades, "remove" or "purge" during removal; RPM
# passes 1 for an upgrade and 0 for an erase.
action="${1:-remove}"
[ "$action" = "0" ] && action="remove"

# Reload systemd after removing service file
systemctl daemon-reload

# Only show removal message on actual removal, not upgrade
if [ "$action" = "remove" ] || [ "$action" = "purge" ]; then
    # Remove sudoers configuration
    rm -f /etc/sudoers.d/gentility /etc/sudoers.d/gentility-gateway

    echo ""
    echo "Gentility AI Agent has been removed."
    echo "User data in /var/lib/gentility-agent and logs in /var/log/gentility-agent have been preserved."
    echo "To completely remove all data, run:"
    echo "  sudo rm -rf /var/lib/gentility-agent /var/log/gentility-agent"
    echo "  sudo userdel gentility"
    echo "  sudo groupdel gentility"
    echo ""
fi
