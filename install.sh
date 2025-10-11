#!/usr/bin/env bash
#
# Gentility Agent Universal Installer
# Usage: curl -sSL https://install.gentility.ai | bash
#        or: wget -qO- https://install.gentility.ai | bash
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)
            PLATFORM="linux"
            ;;
        Darwin*)
            PLATFORM="macos"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log_info "Detected platform: $PLATFORM ($ARCH)"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if we have sudo privileges
check_sudo() {
    if [ "$EUID" -ne 0 ] && ! command_exists sudo; then
        log_error "This script requires sudo privileges, but sudo is not available"
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO="$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')"
        DISTRO_VERSION="$DISTRIB_RELEASE"
    else
        DISTRO="unknown"
    fi

    log_info "Detected distribution: $DISTRO $DISTRO_VERSION"
}

# Install on macOS using Homebrew
install_macos() {
    log_info "Installing Gentility Agent via Homebrew..."

    # Check if Homebrew is installed
    if ! command_exists brew; then
        log_warn "Homebrew not found. Installing Homebrew first..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Add Homebrew to PATH for Apple Silicon Macs
        if [ "$ARCH" = "arm64" ] && [ -f /opt/homebrew/bin/brew ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    fi

    # Install via Homebrew tap
    log_info "Adding Gentility Homebrew tap..."
    brew tap gentility-ai/agent

    log_info "Installing gentility-agent..."
    brew install gentility-agent

    log_info "✓ Installation complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Get your access token from https://dashboard.gentility.ai"
    echo "  2. Run: gentility setup YOUR_TOKEN_HERE"
    echo "  3. Start the agent: gentility run"
}

# Install on Debian/Ubuntu using APT repository
install_apt_repo() {
    log_info "Installing Gentility Agent via APT repository..."

    # Check for required commands
    for cmd in curl gpg; do
        if ! command_exists "$cmd"; then
            log_info "Installing $cmd..."
            sudo apt-get update -qq
            sudo apt-get install -y "$cmd"
        fi
    done

    # Add GPG key
    log_info "Adding GPG key..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://packages.gentility.ai/gentility-packages.gpg | sudo tee /etc/apt/keyrings/gentility-packages.asc > /dev/null

    # Add repository
    log_info "Adding APT repository..."
    echo "deb [signed-by=/etc/apt/keyrings/gentility-packages.asc] https://packages.gentility.ai/debian/ stable main" | sudo tee /etc/apt/sources.list.d/gentility.list > /dev/null

    # Update and install
    log_info "Updating package list..."
    sudo apt-get update -qq

    log_info "Installing gentility-agent..."
    sudo apt-get install -y gentility-agent

    log_info "✓ Installation complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Get your access token from https://dashboard.gentility.ai"
    echo "  2. Run: sudo gentility setup YOUR_TOKEN_HERE"
    echo "  3. Start the service: sudo systemctl start gentility"
    echo "  4. Enable auto-start: sudo systemctl enable gentility"
}

# Install on other Linux distributions using direct DEB package
install_deb_direct() {
    log_info "Installing Gentility Agent via direct DEB package..."

    if [ "$ARCH" != "amd64" ]; then
        log_error "Direct DEB installation currently only supports amd64 architecture"
        log_error "ARM64 support is coming soon"
        exit 1
    fi

    # Get latest version from GitHub releases
    log_info "Fetching latest release information..."

    # Try to get the latest version
    if command_exists curl && command_exists jq; then
        VERSION=$(curl -fsSL https://api.github.com/repos/gentility-ai/agent/releases/latest | jq -r .tag_name | sed 's/^v//')
    else
        # Fallback to a recent known version
        VERSION="1.0.36"
        log_warn "Could not fetch latest version, using v$VERSION"
    fi

    PACKAGE_URL="https://github.com/gentility-ai/agent/releases/download/v${VERSION}/gentility-agent_${VERSION}_amd64.deb"
    PACKAGE_FILE="/tmp/gentility-agent_${VERSION}_amd64.deb"

    # Download package
    log_info "Downloading package from $PACKAGE_URL..."
    if command_exists curl; then
        curl -fsSL -o "$PACKAGE_FILE" "$PACKAGE_URL"
    elif command_exists wget; then
        wget -qO "$PACKAGE_FILE" "$PACKAGE_URL"
    else
        log_error "Neither curl nor wget found. Please install one of them and try again."
        exit 1
    fi

    # Install package
    log_info "Installing package..."
    sudo dpkg -i "$PACKAGE_FILE"

    # Fix dependencies if needed
    if [ $? -ne 0 ]; then
        log_warn "Fixing dependencies..."
        sudo apt-get install -f -y
    fi

    # Clean up
    rm -f "$PACKAGE_FILE"

    log_info "✓ Installation complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Get your access token from https://dashboard.gentility.ai"
    echo "  2. Run: sudo gentility setup YOUR_TOKEN_HERE"
    echo "  3. Start the service: sudo systemctl start gentility"
    echo "  4. Enable auto-start: sudo systemctl enable gentility"
}

# Main installation logic
main() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║   Gentility Agent Universal Installer  ║"
    echo "╚════════════════════════════════════════╝"
    echo ""

    detect_platform

    if [ "$PLATFORM" = "macos" ]; then
        install_macos
    elif [ "$PLATFORM" = "linux" ]; then
        check_sudo
        detect_distro

        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                install_apt_repo
                ;;
            *)
                # For other distributions, try direct DEB package
                log_warn "Distribution '$DISTRO' not officially supported, attempting direct DEB installation..."
                if command_exists dpkg; then
                    install_deb_direct
                else
                    log_error "This distribution doesn't support DEB packages"
                    log_error "Please build from source or use a supported distribution"
                    exit 1
                fi
                ;;
        esac
    fi

    echo ""
    log_info "For more information, visit: https://github.com/gentility-ai/agent"
}

# Run main function
main "$@"
