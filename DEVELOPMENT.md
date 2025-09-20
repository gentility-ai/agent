# Gentility AI Agent - Development Guide

Internal development and deployment instructions for the Gentility AI Agent.

## Building and Packaging

This project uses [Just](https://github.com/casey/just) for build automation and [nfpm](https://nfpm.goreleaser.com/) for packaging.

### Prerequisites

- [Crystal](https://crystal-lang.org/install/) >= 1.0.0
- [Just](https://github.com/casey/just) command runner
- [nfpm](https://nfpm.goreleaser.com/) for packaging
- [aptly](https://www.aptly.info/) for repository management
- GPG for package signing
- rsync and ssh for remote builds (optional)

### Environment Setup

Create a `.env` file with your configuration:

```bash
# Digital Ocean Spaces credentials (for S3-compatible storage)
DO_ACCESS_KEY="your-access-key"
DO_SECRET_KEY="your-secret-key"

# GPG key for package signing
GPG_KEY_ID="your-gpg-key-id"

# Remote build server (optional, for cross-compilation)
CORE7_IP="192.168.1.100"
CORE7_USER="username"
```

### Quick Start

```bash
# Install dependencies
just install-deps

# Build for development
just build-dev

# Run in development mode
just run-dev

# Show build information
just info

# Show all available commands
just
```

### Version Management

The build system uses automatic hash-based version tracking to increment versions when source code changes:

```bash
# Check current version status and source hash
just version-check

# Update version automatically when source changes (called automatically by build commands)
just version-update        # Auto-increments patch version if source changed
just version-update minor  # Force minor version bump
just version-update major  # Force major version bump

# Manual version bump (override automatic detection)
just version-bump patch    # 1.0.0 -> 1.0.1
just version-bump minor    # 1.0.0 -> 1.1.0
just version-bump major    # 1.0.0 -> 2.0.0

# Complete release workflow (fully automated)
just release               # Detects changes, bumps version, builds, and publishes
```

**How it works:**
- SHA256 hash of `src/agent.cr` is compared with stored hash in `.version-lock.json`
- If source changed, version is automatically incremented (patch by default)
- Version is updated in `src/agent.cr`, `nfpm.yaml`, and `nfpm-arm64.yaml`
- History of last 10 versions is kept in the lockfile

### Building for Different Architectures

```bash
# Build AMD64 binary on remote Linux machine (requires CORE7_IP and CORE7_USER in .env)
just build-remote-amd64

# Build ARM64 binary locally (Darwin ARM64 on Mac M1)
just build-local-arm64

# Create DEB packages (includes version checking)
just package-amd64     # Creates AMD64 package (builds on remote)
just package           # Alias for package-amd64

# View available binaries, packages, and version info
just info
```

### Repository Management with Aptly

```bash
# First-time setup (creates GPG key and initializes aptly)
just repo-init
just repo-create

# Add packages to repository
just repo-add-amd64    # Add AMD64 package
just repo-add-all      # Add all available packages

# Publish repository locally
just repo-publish-local

# Publish to Digital Ocean Spaces (S3-compatible)
just repo-publish-s3

# Update existing published repository
just repo-update-s3

# Test repository locally
just test-repo
```

## Architecture Support

### Supported Architectures

- **AMD64 (x86_64)**: Full support with static binary
- **ARM64**: Coming soon

Binary naming convention:
- `gentility-agent-1.0.0-linux-amd64` - Linux AMD64 binary
- `gentility-agent-1.0.0-darwin-arm64` - macOS ARM64 binary (development only)

Package naming convention:
- `gentility-agent_1.0.0_amd64.deb` - Debian package for AMD64
- `gentility-agent_1.0.0_arm64.deb` - Debian package for ARM64 (coming soon)

## Development

```bash
# Install dependencies
just install-deps

# Run tests
just test

# Build development version
just build-dev

# Run with debug logging
just run-dev
```

## Deployment

### Digital Ocean Spaces Configuration

The APT repository is hosted on Digital Ocean Spaces with the following configuration:

- **Endpoint**: `https://gentility.sgp1.digitaloceanspaces.com`
- **Repository URL**: `https://gentility.sgp1.digitaloceanspaces.com/debian/`
- **GPG Key URL**: `https://gentility.sgp1.digitaloceanspaces.com/gentility-packages.gpg`

### Repository Structure

```
debian/
├── dists/
│   └── stable/
│       ├── main/
│       │   └── binary-amd64/
│       │       └── Packages.gz
│       ├── Release
│       ├── Release.gpg
│       └── InRelease
└── pool/
    └── main/
        └── g/
            └── gentility-agent/
                └── gentility-agent_1.0.0_amd64.deb
```

## Security

- All packages are signed with GPG
- Builds are tracked with git commits and tags
- Environment variables are kept in `.env` (never committed)
- Repository is published over HTTPS only

## Troubleshooting

### Build Issues

- Ensure Crystal dependencies are installed: `just install-deps`
- Check remote build server connectivity: `ssh ${CORE7_USER}@${CORE7_IP}`
- Verify GPG key exists: `gpg --list-secret-keys`

### Repository Issues

- Test repository locally: `just test-repo`
- Verify GPG signing: `just validate-package`
- Check aptly configuration: `aptly -config=configs/aptly.conf repo show gentility-main`

## License

MIT License - see LICENSE file for details.