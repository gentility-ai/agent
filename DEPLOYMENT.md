# Gentility AI Agent - Deployment Guide

This repo still supports package publishing, but the current surface is narrower than the historical docs implied. This guide covers the workflows that still exist in the repository today.

## Current Deployment Surfaces

1. GitHub Actions builds release artifacts from `.github/workflows/build.yml`.
2. `just release` is the local version/tag workflow.
3. `aptly` plus `nfpm` powers the local package repository flow.
4. `ansible/` contains the remaining package-server helpers.

## Prerequisites

- GPG key for package signing
- `aptly`
- `nfpm`
- `ansible` only if you use the package-server playbooks
- Optional `.env` values for:
  - `GPG_KEY_ID`
  - `DO_ACCESS_KEY`
  - `DO_SECRET_KEY`

## Local Package Repository Flow

GitHub Actions is now the build source for release artifacts. Start by downloading the `.deb` file you want to publish into `./packages/`.

```bash
just install-tools
just repo-init
just repo-create
just repo-add-amd64
# or:
just repo-add-package packages/gentility-agent_<version>_amd64.deb
just repo-publish-local
just test-repo
just validate-package
```

That flow produces a local APT repository under `public/`.

## DigitalOcean Spaces Publishing

If you still publish the repository to Spaces:

```bash
just repo-publish-s3
```

For updating an existing published repo after adding a package:

```bash
just repo-update-s3
```

The `justfile` expects the Spaces credentials in `.env`.

## Package Server Helpers

The remaining server automation lives here:

- `ansible/playbooks/setup-server.yml`
- `ansible/playbooks/deploy-packages.yml`
- `ansible/inventory/hosts.yml`
- `configs/aptly.conf`
- `configs/aptly-s3.conf`

Use the helpers only if that package server is still part of your deployment:

```bash
just setup-server
just deploy-packages
```

## GitHub Releases

The repository already has a build workflow in `.github/workflows/build.yml`. On pushes, PRs, and tags it builds:

- Linux AMD64 artifacts
- Linux ARM64 artifacts
- macOS ARM64 artifacts

For the local tagged release path:

```bash
just release
```

That workflow bumps the version, commits, creates the tag, and pushes it. GitHub Actions then builds and publishes the release artifacts for that tag.

## User Installation

### Debian / Ubuntu

```bash
sudo mkdir -p /etc/apt/keyrings
curl -s https://packages.gentility.ai/gentility-packages.gpg | sudo tee /etc/apt/keyrings/gentility-packages.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/gentility-packages.asc] https://packages.gentility.ai/debian/ stable main" | sudo tee /etc/apt/sources.list.d/gentility.list
sudo apt update
sudo apt install gentility-agent
```

### macOS

```bash
brew tap gentility-ai/agent
brew install gentility-agent
```

## Troubleshooting

```bash
# Inspect aptly repo state
just repo-show

# Verify signatures in the generated repo
just validate-package

# Serve the local repo for manual testing
just test-repo
```

If repository publishing fails, check:

- GPG key availability: `gpg --list-secret-keys`
- `aptly` config in `configs/aptly.conf`
- Spaces credentials in `.env`
