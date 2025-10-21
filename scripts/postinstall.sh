#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# Set proper ownership
chown -R gentility:gentility /var/log/gentility-agent
chown -R gentility:gentility /var/lib/gentility-agent

# Migrate old .conf to .yaml if it exists
if [ -f /etc/gentility.conf ] && [ ! -f /etc/gentility.yaml ]; then
    echo "Migrating configuration from .conf to .yaml format..."

    # Create YAML header
    cat > /etc/gentility.yaml << 'YAML_HEADER'
# Gentility AI Agent Configuration
# Migrated from gentility.conf

YAML_HEADER

    # Convert shell variables to YAML format
    # Handle quoted and unquoted values
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # Skip empty lines and comments
        [ -z "$key" ] && continue
        echo "$key" | grep -q '^#' && continue
        echo "$key" | grep -q '^[[:space:]]*$' && continue

        # Remove leading/trailing whitespace from key
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip if no key
        [ -z "$key" ] && continue

        # Remove quotes from value if present
        value=$(echo "$value" | sed "s/^['\"]//;s/['\"]$//")

        # Convert to snake_case YAML key
        yaml_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')

        # Handle security section separately
        case "$key" in
            SECURITY_MODE|SECURITY_PASSWORD|SECURITY_TOTP_SECRET|SECURITY_UNLOCK_TIMEOUT|SECURITY_EXTENDABLE|PROMISCUOUS_ENABLED|PROMISCUOUS_AUTH_MODE)
                # These will be handled in the security section
                ;;
            GENTILITY_TOKEN)
                echo "access_key: \"$value\"" >> /etc/gentility.yaml
                ;;
            SERVER_URL|NICKNAME|ENVIRONMENT)
                echo "$yaml_key: \"$value\"" >> /etc/gentility.yaml
                ;;
            DEBUG)
                echo "$yaml_key: $value" >> /etc/gentility.yaml
                ;;
        esac
    done < /etc/gentility.conf

    # Add security section if any security settings exist
    if grep -q '^SECURITY_' /etc/gentility.conf || grep -q '^PROMISCUOUS_' /etc/gentility.conf; then
        echo "" >> /etc/gentility.yaml
        echo "security:" >> /etc/gentility.yaml

        # Extract security settings
        while IFS='=' read -r key value || [ -n "$key" ]; do
            # Skip empty lines and comments
            [ -z "$key" ] && continue
            echo "$key" | grep -q '^#' && continue

            # Remove quotes from value
            value=$(echo "$value" | sed "s/^['\"]//;s/['\"]$//")

            case "$key" in
                SECURITY_MODE)
                    echo "  mode: \"$value\"" >> /etc/gentility.yaml
                    ;;
                SECURITY_PASSWORD)
                    echo "  password: \"$value\"" >> /etc/gentility.yaml
                    ;;
                SECURITY_TOTP_SECRET)
                    echo "  totp_secret: \"$value\"" >> /etc/gentility.yaml
                    ;;
                SECURITY_UNLOCK_TIMEOUT)
                    echo "  unlock_timeout: $value" >> /etc/gentility.yaml
                    ;;
                SECURITY_EXTENDABLE)
                    echo "  extendable: $value" >> /etc/gentility.yaml
                    ;;
                PROMISCUOUS_ENABLED)
                    echo "  promiscuous_enabled: $value" >> /etc/gentility.yaml
                    ;;
                PROMISCUOUS_AUTH_MODE)
                    echo "  promiscuous_auth_mode: \"$value\"" >> /etc/gentility.yaml
                    ;;
            esac
        done < /etc/gentility.conf
    fi

    # Add encrypted_db_credentials section
    echo "" >> /etc/gentility.yaml
    echo "# Encrypted database credentials (managed by server)" >> /etc/gentility.yaml
    echo "encrypted_db_credentials: {}" >> /etc/gentility.yaml

    # Set proper permissions - readable by gentility user
    chmod 640 /etc/gentility.yaml
    chown gentility:gentility /etc/gentility.yaml

    # Backup old config
    mv /etc/gentility.conf /etc/gentility.conf.bak
    echo "Migration complete. Old config backed up to /etc/gentility.conf.bak"
fi

# Create default config file if it doesn't exist
if [ ! -f /etc/gentility.yaml ]; then
    cp /etc/gentility.yaml.example /etc/gentility.yaml
    chmod 640 /etc/gentility.yaml
    chown gentility:gentility /etc/gentility.yaml
fi

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable gentility

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
echo "View logs:"
echo "  sudo journalctl -u gentility -f"
echo ""
echo "For help:"
echo "  gentility help"
echo ""
