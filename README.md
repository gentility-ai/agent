# Gentility AI Agent

A secure, lightweight WebSocket-based agent daemon that connects your privileged environment to Gentility AI servers for intelligent system administration and automation.

## Features

- **Real-time WebSocket communication** with Gentility AI servers
- **System information collection** and reporting
- **Remote command execution** capabilities (with proper authorization)
- **Database query execution** (PostgreSQL and MySQL)
- **File read/write operations** (secure, sandboxed)
- **Capability checking** and validation
- **Systemd integration** for reliable service management

## Supported Platforms

- **Linux AMD64** (x86_64) - Primary support with static binaries
- **Linux ARM64** - Coming soon

Tested on Ubuntu 20.04+, Debian 11+, CentOS 8+, and other modern Linux distributions.

## Installation

### Option 1: APT Repository (Recommended)

Add the Gentility AI package repository to your system:

```bash
# Add GPG key for package verification (modern method)
sudo mkdir -p /etc/apt/keyrings
curl -s https://gentility.sgp1.digitaloceanspaces.com/gentility-packages.gpg | sudo tee /etc/apt/keyrings/gentility-packages.asc > /dev/null

# Add repository with signed-by specification
echo "deb [signed-by=/etc/apt/keyrings/gentility-packages.asc] https://gentility.sgp1.digitaloceanspaces.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/gentility.list

# Update package list and install
sudo apt update
sudo apt install gentility-agent
```

### Option 2: Direct DEB Package

Download and install the latest package directly:

```bash
# Download the latest package
wget https://gentility.sgp1.digitaloceanspaces.com/debian/pool/main/g/gentility-agent/gentility-agent_1.0.0_amd64.deb

# Install the package
sudo dpkg -i gentility-agent_1.0.0_amd64.deb

# Install any missing dependencies
sudo apt-get install -f
```

### Option 3: Build from Source

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
crystal build src/agent.cr --release --static -o gentility-agent

# Install manually (optional)
sudo cp gentility-agent /usr/local/bin/gentility-agent
sudo chmod +x /usr/local/bin/gentility-agent
```

## Quick Start

After installation, you need to configure the agent with your access token:

```bash
# Copy the example configuration
sudo cp /etc/gentility.conf.example /etc/gentility.conf

# Edit the configuration with your details
sudo nano /etc/gentility.conf
```

**Required configuration:**
```bash
GENTILITY_TOKEN="your-access-token-here"
```

Start the service:
```bash
# Start and enable the service
sudo systemctl start gentility-agent
sudo systemctl enable gentility-agent

# Check status
sudo systemctl status gentility-agent
```

## Configuration

The agent is configured through `/etc/gentility.conf`.

### Configuration File

The only required configuration is your access token:

```bash
# /etc/gentility.conf
GENTILITY_TOKEN="gnt_1234567890abcdef"
```

Get your access token from your Gentility AI dashboard.

## Service Management

The agent runs as a systemd service and can be managed with standard commands:

```bash
# Check service status
sudo systemctl status gentility-agent

# Start/stop the service
sudo systemctl start gentility-agent
sudo systemctl stop gentility-agent
sudo systemctl restart gentility-agent

# Enable/disable automatic startup
sudo systemctl enable gentility-agent
sudo systemctl disable gentility-agent

# View logs
sudo journalctl -u gentility-agent -f
sudo journalctl -u gentility-agent --since="1 hour ago"
```

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check configuration file
sudo cat /etc/gentility.conf

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

- **Service logs**: `sudo journalctl -u gentility-agent`
- **Application logs**: `/var/log/gentility-agent/` (if configured)

## Security

- The agent uses secure WebSocket connections (WSS) with TLS encryption
- All packages are cryptographically signed
- The agent runs with minimal privileges
- Configuration files are protected with appropriate permissions
- No sensitive data is stored in logs

## Support

For support, issues, or feature requests:

- **GitHub Issues**: [Create an issue](https://github.com/gentility-ai/gentility-agent/issues)
- **Documentation**: [docs.gentility.ai](https://docs.gentility.ai)
- **Email**: support@gentility.ai

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## For Developers

If you're interested in contributing or building from source, see [DEVELOPMENT.md](DEVELOPMENT.md) for build instructions and development guidelines.
