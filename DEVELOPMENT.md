# Gentility AI Agent - Development Guide

Internal build and release notes for the Gentility AI Agent.

## Tooling

- [Crystal](https://crystal-lang.org/install/) >= 1.0.0
- [Just](https://github.com/casey/just)
- [nfpm](https://nfpm.goreleaser.com/) for DEB/RPM packaging
- [aptly](https://www.aptly.info/) and GPG for the package repository workflow
- `ssh` and `rsync` only if you use the remote AMD64 build path

## Environment Setup

Create a `.env` file only for the workflows you actually use:

```bash
# Optional: remote Linux build host
CORE7_IP="192.168.1.100"
CORE7_USER="username"

# Optional: package signing / DigitalOcean Spaces publishing
GPG_KEY_ID="your-gpg-key-id"
DO_ACCESS_KEY="your-access-key"
DO_SECRET_KEY="your-secret-key"
```

## Quick Start

```bash
just install-deps
just build-dev
just test
just run-dev
just info
```

## Versioning

`VERSION` is the release source of truth.

```bash
just version
just version-bump patch
just version-bump minor
just version-bump major
```

For tagged releases:

```bash
just release
```

If you want to handle tagging manually after bumping:

```bash
just release-commit
```

GitHub Actions in `.github/workflows/build.yml` builds the published release artifacts on pushes, PRs, and tags.

## Build Targets

```bash
# Native development build
just build-dev

# Native release build for the current platform
just build

# Remote Linux AMD64 build
just build-remote-amd64

# macOS binaries
just build-macos
just build-local-arm64
just build-local-x86_64

# Packages
just package-amd64
just package-macos
```

The local `justfile` packaging flow is centered on AMD64 Linux packages. Multi-arch release artifacts are produced in CI.

## Package Repository Workflow

```bash
# One-time local repo setup
just install-tools
just repo-init
just repo-create

# Build and add a package
just package-amd64
just repo-add-amd64

# Publish locally and test
just repo-publish-local
just test-repo
just validate-package
```

For DigitalOcean Spaces publishing:

```bash
just repo-publish-s3
# or, after a package has already been added:
just repo-update-s3
```

For the package server deployment helpers:

```bash
just deploy-packages
just setup-server
```

## Troubleshooting

### Build Issues

- Ensure dependencies are installed: `just install-deps`
- Check remote build connectivity if you use it: `ssh ${CORE7_USER}@${CORE7_IP}`
- Verify signing keys: `gpg --list-secret-keys`

### Repository Issues

- Test the generated repo locally: `just test-repo`
- Verify signatures: `just validate-package`
- Inspect aptly state: `aptly -config=configs/aptly.conf repo show gentility-main`

## License

MIT License - see `LICENSE`.
