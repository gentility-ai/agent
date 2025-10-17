# Gentility AI Agent

A lightweight daemon that connects your servers and computers to Gentility AI.

## Features

- **Simple and Auditable** trust, but verify
- **Local credential capability** so your secrets stay with you
- **Database query execution** (PostgreSQL and MySQL)
- **File read/write operations** (when enabled)
- **Lockable** for ultimate peace of mind

## Supported Platforms

- **Linux AMD64** (x86_64) - Primary support with static binaries
- **Linux ARM64** - Coming soon
- **macOS** (Intel and Apple Silicon) - Homebrew support

Tested on Ubuntu 20.04+, Debian 11+, CentOS 8+, and other modern Linux distributions.
macOS 10.15+ supported via Homebrew.

## Installation

### Option 0: If you're in a hurry

### Option 1: APT Repository (Recommended)

Add the Gentility AI package repository to your system:

```bash
# Add GPG key for package verification (modern method)
sudo mkdir -p /etc/apt/keyrings
curl -s https://packages.gentility.ai/gentility-packages.gpg | sudo tee /etc/apt/keyrings/gentility-packages.asc > /dev/null

# Add repository with signed-by specification
echo "deb [signed-by=/etc/apt/keyrings/gentility-packages.asc] https://packages.gentility.ai/debian/ stable main" | sudo tee /etc/apt/sources.list.d/gentility.list

# Update package list and install
sudo apt update
sudo apt install gentility-agent
```

### Option 2: Direct DEB Package

Download and install the latest package directly:

```bash
# Download the latest package
wget https://github.com/gentility-ai/agent/releases/download/v1.1.1/gentility-agent_1.1.8_amd64.deb

# Install the package
sudo dpkg -i gentility-agent_1.1.8_amd64.deb

# Install any missing dependencies
sudo apt-get install -f
```

### Option 3: Homebrew (macOS)

Install via the Gentility Homebrew tap:

```bash
brew tap gentility-ai/agent
brew install gentility-agent
```

### Option 4: Build from Source

Build and install from the official source code:

```bash
# Install Crystal language (if not already installed)
curl -fsSL https://crystal-lang.org/install.sh | sudo bash

# Clone the source repository
git clone https://github.com/gentility-ai/agent.git
cd agent

# Install dependencies
shards install

# Build the binary
crystal build src/agent.cr --release --static -o gentility

# Install manually (optional)
sudo cp gentility /usr/local/bin/gentility
sudo chmod +x /usr/local/bin/gentility
```

## Quick Start

After installation, configure the agent with your access token using the setup command:

```bash
# Quick setup (recommended) - Creates or updates configuration
gentility auth
```

The `auth` command will:

- Create a new config file if none exists
- Take you to Gentility to associate this installation with an account

**How to run:**

Start the service:

```bash
# Start and enable the service
sudo systemctl start gentility
sudo systemctl enable gentility

# Check status
sudo systemctl status gentility

# View real-time logs
sudo journalctl -u gentility-agent -f
```

## Uninstallation

To completely remove the agent from your system:

```bash
# Stop and disable the service
sudo systemctl stop gentility
sudo systemctl disable gentility

# Remove the package
sudo apt remove gentility-agent

# Optional: Remove configuration and logs
sudo rm -rf /etc/gentility.yaml
sudo rm -rf /var/log/gentility-agent
sudo rm -rf /var/lib/gentility-agent

# Optional: Remove repository from sources
sudo rm /etc/apt/sources.list.d/gentility.list
sudo rm /etc/apt/keyrings/gentility-packages.asc
```

## Configuration

The agent is configured through `/etc/gentility.yaml`.

### Configuration File

The only required configuration is your access token:

```bash
# /etc/gentility.yaml
GENTILITY_TOKEN="gnt_1234567890abcdef"
```

Get your access token from your Gentility AI dashboard.

### Advanced Configuration Options

The configuration file supports additional security and operational settings:

```bash
# /etc/gentility.yaml

# Required: Your access token
GENTILITY_TOKEN="gnt_1234567890abcdef"

# Optional: Server connection settings
SERVER_URL="wss://core.gentility.ai"  # Default server
NICKNAME="my-server"                 # Agent nickname (default: hostname)
ENVIRONMENT="prod"                   # Environment: prod or staging
DEBUG="false"                        # Enable debug logging

# Security settings
SECURITY_MODE="none"                 # Security mode: none, password, totp
SECURITY_PASSWORD="mypassword"       # Password for password mode
SECURITY_TOTP_SECRET="ABC123..."     # TOTP secret for TOTP mode
SECURITY_UNLOCK_TIMEOUT="1800"   # Security timeout in seconds (30 minutes)
SECURITY_EXTENDABLE="true"           # Allow extending security sessions

# Promiscuous mode (allows config sharing)
PROMISCUOUS_ENABLED="true"           # Enable promiscuous mode
PROMISCUOUS_AUTH_MODE="password"     # Auth mode for promiscuous operations
```

## Service Management

The agent runs as a systemd service and can be managed with standard commands:

```bash
# Check service status
sudo systemctl status gentility

# Start/stop the service
sudo systemctl start gentility
sudo systemctl stop gentility
sudo systemctl restart gentility

# Enable/disable automatic startup
sudo systemctl enable gentility
sudo systemctl disable gentility

# View logs
sudo journalctl -u gentility -f
sudo journalctl -u gentility --since="1 hour ago"
```

## Troubleshooting

### Common Issues

**Service won't start:**

```bash
# Check configuration file
sudo cat /etc/gentility.yaml

# Check service logs
sudo journalctl -u gentility-agent --no-pager
```

**Connection issues:**

```bash
# Test connectivity (if server is reachable)
curl -I https://api.gentility.ai

# Check firewall (port 443 outbound should be open)
sudo ufw status
```

**Authentication errors:**

- Verify your `GENTILITY_TOKEN` is correct
- Check that the token hasn't expired
- Ensure the token has appropriate permissions

### Log Locations

- **Service logs**: `sudo journalctl -u gentility`
- **Application logs**: `/var/log/gentility/` (if configured)

## Security

- The agent uses secure WebSocket connections (WSS) with TLS encryption
- All packages are cryptographically signed
- The agent runs with minimal privileges
- Configuration files are protected with appropriate permissions
- No sensitive data is stored in logs

### Rate Limiting

The agent supports password and TOTP authentication with built-in rate limiting to prevent brute-force attacks.

After 5 failed authentication attempts, the agent enters lockout mode. Each failed attempt enforces an exponential backoff delay (30s, 60s, 120s, 240s).

See [docs/SECURITY_RATE_LIMITING.md](docs/SECURITY_RATE_LIMITING.md) for details.

## Support

For support, issues, or feature requests:

- **GitHub Issues**: [Create an issue](https://github.com/gentility-ai/agent/issues)
- **Documentation**: [docs.gentility.ai](https://docs.gentility.ai)
- **Email**: support@gentility.ai

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Command Line Interface

The `gentility` command provides several modes of operation:

### Basic Usage

```bash
# Show help and available commands
gentility
gentility help

# Start the agent daemon
gentility run --token=YOUR_TOKEN_HERE
gentility start --token=YOUR_TOKEN_HERE --debug
```

**Note**: The agent no longer starts automatically. You must explicitly use the `run` or `start` command.

### Setup Commands

```bash
sudo gentility auth

gentility run
```

### Security Configuration

The agent supports multiple security modes to protect sensitive operations:

#### TOTP Authentication (Recommended)

```bash
# Enable TOTP with auto-generated secret
sudo gentility security totp

# Enable TOTP with custom secret
sudo gentility security totp ABC123DEF456GHI789

# Test your TOTP setup
sudo gentility test-totp 123456
```

TOTP setup will display a QR code that you can scan with any authenticator app (Google Authenticator, Authy, 1Password, etc.). The QR code is generated as ASCII art directly in your terminal.

#### Password Authentication

```bash
# Enable password security (prompts for password)
sudo gentility security password

# Enable password security with inline password
sudo gentility security password mySecretPassword123
```

#### Disable Security

```bash
# Disable all security (not recommended for production)
sudo gentility security none
```

### Promiscuous Mode

Promiscuous mode allows the server to export and share security configuration across multiple agents:

```bash
# Enable promiscuous mode
sudo gentility promiscuous enable

# Disable promiscuous mode
sudo gentility promiscuous disable

# Check promiscuous mode status
sudo gentility promiscuous status

# Set promiscuous authentication mode
sudo gentility promiscuous auth password  # or 'totp'
```

### Configuration Priority

Configuration is loaded in this order (later sources override earlier ones):

1. **Default values** (built into the application)
2. **Configuration file** (`/etc/gentility.yaml`)
3. **Environment variables** (`GENTILITY_TOKEN`, `SERVER_URL`, etc.)
4. **Command line arguments** (`--token=`, `--debug`)

### Environment Variables

All configuration options can be set via environment variables:

```bash
export GENTILITY_TOKEN="your-token-here"
export SERVER_URL="wss://your-server.com"
export NICKNAME="my-custom-name"
export ENVIRONMENT="staging"
export DEBUG="true"

# Then start the agent
gentility run
```

### Security Features

- **Unlock timeout**: Security sessions expire after 30 minutes by default
- **Extendable sessions**: Each command execution extends the security session
- **Hard timeout**: Sessions have an absolute maximum duration from first unlock
- **Multiple auth modes**: Support for both TOTP and password authentication
- **Secure storage**: All security settings are stored with 600 permissions in `/etc/gentility.yaml`
- **QR code generation**: TOTP setup includes ASCII QR codes for easy authenticator app configuration

### Complete Command Reference

```bash
# Main Commands
gentility                           # Show help
gentility run [options]             # Start the agent daemon
gentility start [options]           # Alias for 'run'
gentility help                      # Show help

# Setup and Configuration
gentility setup <token>             # Initial setup
gentility security <mode> [value]   # Configure security
gentility test-totp <code>          # Test TOTP validation
gentility promiscuous <action>      # Configure promiscuous mode

# Run Options
--token=<token>                     # Access token
--debug                             # Enable debug logging

# Security Modes
security totp [secret]              # TOTP authentication
security password [password]        # Password authentication
security none                       # No security

# Promiscuous Actions
promiscuous enable                  # Enable promiscuous mode
promiscuous disable                 # Disable promiscuous mode
promiscuous status                  # Show status
promiscuous auth <mode>             # Set auth mode (password|totp)
```

## For Developers

If you're interested in contributing or building from source, see [DEVELOPMENT.md](DEVELOPMENT.md) for build instructions and development guidelines.
