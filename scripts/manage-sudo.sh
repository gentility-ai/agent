#!/bin/sh
# Gentility AI Agent - Sudo Access Manager
# Manages /etc/sudoers.d/gentility for the gentility system user.
# Must be run as root (except for status command).
set -e

SUDOERS_FILE="/etc/sudoers.d/gentility"
SUDOERS_TMP="/tmp/gentility-sudoers.tmp"
AGENT_USER="gentility"

# Limited sudo: package management, service control, log viewing
SUDOERS_LIMITED="# Gentility AI Agent - limited sudo access
# Allows: package management, service control, log viewing
${AGENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/systemctl, /usr/bin/journalctl, /usr/bin/snap"

# Full sudo: unrestricted
SUDOERS_FULL="# Gentility AI Agent - full sudo access
${AGENT_USER} ALL=(ALL) NOPASSWD: ALL"

usage() {
    echo "Usage: manage-sudo.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  enable [limited|full]  Grant sudo access (default: full)"
    echo "  disable                Remove sudo access"
    echo "  status                 Show current sudo configuration"
    echo ""
    echo "Must be run as root (except for status)."
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: This command must be run as root (use sudo)."
        exit 1
    fi
}

do_enable() {
    level="${1:-full}"

    case "$level" in
        limited)
            echo "$SUDOERS_LIMITED" > "$SUDOERS_TMP"
            label="limited"
            ;;
        full)
            echo "$SUDOERS_FULL" > "$SUDOERS_TMP"
            label="full"
            ;;
        *)
            echo "Error: Unknown sudo level '$level'. Use 'limited' or 'full'."
            exit 1
            ;;
    esac

    # Validate with visudo before installing
    if visudo -cf "$SUDOERS_TMP" >/dev/null 2>&1; then
        chmod 0440 "$SUDOERS_TMP"
        chown root:root "$SUDOERS_TMP"
        mv "$SUDOERS_TMP" "$SUDOERS_FILE"
        echo "Sudo access enabled for gentility agent ($label)."
    else
        rm -f "$SUDOERS_TMP"
        echo "Error: Generated sudoers file failed validation. No changes made."
        exit 1
    fi
}

do_disable() {
    if [ -f "$SUDOERS_FILE" ]; then
        rm -f "$SUDOERS_FILE"
        echo "Sudo access removed for gentility agent."
    else
        echo "Sudo access is not currently enabled."
    fi
}

do_status() {
    if [ ! -f "$SUDOERS_FILE" ]; then
        echo "none"
        return
    fi

    if grep -q "NOPASSWD: ALL" "$SUDOERS_FILE"; then
        echo "full"
    else
        echo "limited"
    fi
}

# Main dispatch
case "${1:-}" in
    enable)
        check_root
        do_enable "${2:-full}"
        ;;
    disable)
        check_root
        do_disable
        ;;
    status)
        do_status
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "Error: Unknown command '$1'"
        usage
        exit 1
        ;;
esac
