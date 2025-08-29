#!/bin/sh
# Reload systemd after removing service file
systemctl daemon-reload

echo ""
echo "Gentility AI Agent has been removed."
echo "User data in /var/lib/gentility-agent and logs in /var/log/gentility-agent have been preserved."
echo "To completely remove all data, run:"
echo "  sudo rm -rf /var/lib/gentility-agent /var/log/gentility-agent"
echo "  sudo userdel gentility"
echo "  sudo groupdel gentility"
echo ""