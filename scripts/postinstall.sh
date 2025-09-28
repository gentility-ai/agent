#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# Set proper ownership
chown -R gentility:gentility /var/log/gentility-agent
chown -R gentility:gentility /var/lib/gentility-agent

# Create default config file if it doesn't exist
if [ ! -f /etc/gentility.conf ]; then
    cp /etc/gentility.conf.example /etc/gentility.conf
    chmod 600 /etc/gentility.conf
    chown root:root /etc/gentility.conf
fi

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable gentility

echo ""
echo "Gentility AI Agent has been installed successfully!"
echo ""
echo "Before starting the service, please configure your access token:"
echo "  1. Copy the example config: sudo cp /etc/gentility.conf.example /etc/gentility.conf"
echo "  2. Edit the config file: sudo nano /etc/gentility.conf"
echo "  3. Set your GENTILITY_TOKEN in the config file"
echo ""
echo "Then start the service:"
echo "  sudo systemctl start gentility"
echo "  sudo systemctl status gentility"
echo ""
echo "View logs:"
echo "  sudo journalctl -u gentility -f"
echo ""