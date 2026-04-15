#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# Set proper ownership
chown -R gentility:gentility /var/log/gentility-agent
chown -R gentility:gentility /var/lib/gentility-agent

read_with_timeout() {
    output_file="$1"
    timeout_secs="${2:-30}"

    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_secs" sh -c '
            IFS= read -r value || exit 1
            printf "%s\n" "$value" > "$1"
        ' sh "$output_file"
        return $?
    fi

    IFS= read -r value || return 1
    printf "%s\n" "$value" > "$output_file"
}

# Create default config file if it doesn't exist
if [ ! -f /etc/gentility.yaml ]; then
    cp /etc/gentility.yaml.example /etc/gentility.yaml
    chmod 640 /etc/gentility.yaml
    chown gentility:gentility /etc/gentility.yaml
fi

# Offer sudo configuration if running interactively
MANAGE_SUDO="/usr/lib/gentility-agent/manage-sudo.sh"
if [ -t 0 ] && [ -f "$MANAGE_SUDO" ] && [ ! -f /etc/sudoers.d/gentility ]; then
    echo ""
    echo "Would you like to grant the gentility agent sudo access?"
    echo "  1) No sudo access (default)"
    echo "  2) Limited (apt, systemctl, journalctl, dpkg, snap)"
    echo "  3) Full (unrestricted)"
    printf "Choose [1-3]: "

    # Read with a timeout using POSIX sh-compatible tools.
    if sudo_choice_file=$(mktemp /tmp/gentility-sudo-choice.XXXXXX); then
        if read_with_timeout "$sudo_choice_file" 30 < /dev/tty; then
            sudo_choice=$(cat "$sudo_choice_file")
            case "$sudo_choice" in
                2)
                    "$MANAGE_SUDO" enable limited
                    ;;
                3)
                    "$MANAGE_SUDO" enable full
                    ;;
                *)
                    echo "No sudo access configured."
                    ;;
            esac
        else
            echo ""
            echo "No input received, skipping sudo configuration."
        fi
        rm -f "$sudo_choice_file"
    else
        echo ""
        echo "Could not create a temporary file, skipping sudo configuration."
    fi
fi

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable gentility

# Check if service was running before upgrade and restart it
if [ -f /var/lib/gentility-agent/.was-running ]; then
    rm -f /var/lib/gentility-agent/.was-running
    echo "Restarting service after upgrade..."
    systemctl start gentility
fi

echo ""
echo "Gentility AI Agent has been installed successfully!"
echo ""
echo "Next steps:"
echo ""
echo "  1. Authenticate and provision this agent:"
echo "     sudo gentility auth"
echo ""
echo "     This will:"
echo "       - Open OAuth authentication in your browser"
echo "       - Connect to Gentility AI servers"
echo "       - Provision a machine key automatically"
echo "       - Save configuration to /etc/gentility.yaml"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start gentility"
echo "     sudo systemctl status gentility"
echo ""
echo "  3. (Optional) Install database client tools:"
echo "     If you plan to use this agent as a database proxy,"
echo "     install the relevant client for your database:"
echo ""
echo "     PostgreSQL:  sudo apt install postgresql-client"
echo "     MySQL:       sudo apt install mysql-client"
echo ""
echo "  4. (Optional) Configure sudo access:"
echo "     sudo gentility enable-sudo limited   # apt, systemctl, journalctl"
echo "     sudo gentility enable-sudo full      # unrestricted sudo"
echo "     sudo gentility disable-sudo          # remove sudo access"
echo ""
echo "View logs:"
echo "  sudo journalctl -u gentility -f"
echo ""
echo "For help:"
echo "  gentility help"
echo ""
