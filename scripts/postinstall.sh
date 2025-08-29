#!/bin/sh
# Set proper ownership
chown -R gentility:gentility /var/log/gentility-agent
chown -R gentility:gentility /var/lib/gentility-agent

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable gentility-agent

echo ""
echo "Gentility AI Agent has been installed successfully!"
echo ""
echo "Before starting the service, please configure your access token:"
echo "  1. Copy the example config: sudo cp /etc/gentility.conf.example /etc/gentility.conf"
echo "  2. Edit the config file: sudo nano /etc/gentility.conf"
echo "  3. Set your GENTILITY_TOKEN in the config file"
echo ""
echo "Then start the service:"
echo "  sudo systemctl start gentility-agent"
echo "  sudo systemctl status gentility-agent"
echo ""
echo "View logs:"
echo "  sudo journalctl -u gentility-agent -f"
echo ""