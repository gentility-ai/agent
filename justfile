# Gentility AI Agent - Build and Packaging with Just

binary_name := "gentility-agent"
bin_dir := "bin"
# Default to amd64 for production deployments
arch := env_var_or_default("TARGET_ARCH", "amd64")

# Read version from VERSION file
version := `cat VERSION 2>/dev/null || echo "1.0.0"`
deb_file := "packages/" + binary_name + "_" + version + "_" + arch + ".deb"

# Show available commands
default:
    @just --list

# Install Crystal dependencies
install-deps:
    @echo "Installing Crystal dependencies..."
    shards install

# Release binaries (Linux amd64/arm64, macOS arm64) are built by the
# GitHub Actions workflow on tag push — see `just release`. This
# recipe is for local iteration only.
# Build a development binary for the current platform
build-dev: install-deps
    @echo "Building {{binary_name}} v{{version}} for development..."
    @mkdir -p {{bin_dir}}
    crystal build src/agent.cr -o {{bin_dir}}/{{binary_name}}
    @echo "Development binary built: {{bin_dir}}/{{binary_name}}"

# CI publishes .deb (amd64/arm64), .rpm (x86_64/aarch64), and .tar.gz
# (linux amd64/arm64, darwin arm64) on every v* tag.
# Download the GitHub Actions release artifacts for the current VERSION into ./packages
fetch-release:
    #!/bin/bash
    set -e
    current_version=$(cat VERSION)
    tag="v${current_version}"
    echo "📥 Fetching release artifacts for ${tag} from GitHub..."
    mkdir -p packages
    if ! gh release view "${tag}" >/dev/null 2>&1; then
        echo "❌ Release ${tag} does not exist yet."
        echo "   Tag it with 'just release' and wait for the Build workflow to finish."
        exit 1
    fi
    gh release download "${tag}" --dir packages --clobber
    echo ""
    echo "✅ Downloaded release artifacts for ${tag}:"
    ls -lh "packages/{{binary_name}}"*"${current_version}"* 2>/dev/null || true

# Add specific package to aptly repository
repo-add-package package_file repo_name="gentility-main":
    @echo "Adding {{package_file}} to aptly repository '{{repo_name}}'..."
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{package_file}}
    @echo "Package added to repository"

# Add AMD64 package to aptly repository
repo-add-amd64 repo_name="gentility-main":
    @echo "Adding AMD64 package to aptly repository '{{repo_name}}'..."
    @if [ ! -f "packages/{{binary_name}}_{{version}}_amd64.deb" ]; then \
        echo "Error: packages/{{binary_name}}_{{version}}_amd64.deb not found."; \
        echo "Run 'just fetch-release' to download the CI-built package from GitHub."; \
        exit 1; \
    fi
    aptly -config=configs/aptly.conf repo add {{repo_name}} packages/{{binary_name}}_{{version}}_amd64.deb
    @echo "AMD64 package added to repository"

# Expects packages/ to already contain the artifacts fetched from GitHub
# via `just fetch-release`.
# Add all deb packages for the current version to the aptly repository
repo-add-all repo_name="gentility-main":
    @echo "Adding all packages to repository..."
    @if ! ls packages/{{binary_name}}_{{version}}_*.deb >/dev/null 2>&1; then \
        echo "Error: no packages/{{binary_name}}_{{version}}_*.deb found."; \
        echo "Run 'just fetch-release' to download the CI-built packages from GitHub."; \
        exit 1; \
    fi
    @for pkg in packages/{{binary_name}}_{{version}}_*.deb; do \
        if [ -f "$$pkg" ]; then \
            echo "Adding $$pkg..." && \
            aptly -config=configs/aptly.conf repo add {{repo_name}} $$pkg; \
        fi \
    done
    @echo "All packages added to repository"

# Legacy repo-add (defaults to AMD64)
repo-add repo_name="gentility-main": repo-add-amd64

# Publish repository with aptly
repo-publish repo_name="gentility-main" distribution="stable":
    @echo "Publishing repository '{{repo_name}}' for distribution '{{distribution}}'..."
    aptly -config=configs/aptly.conf publish repo {{repo_name}} {{distribution}}
    @echo "Repository published"

# Update published repository
repo-update repo_name="gentility-main" distribution="stable":
    @echo "Updating repository with new package..."
    @if [ ! -f "{{deb_file}}" ]; then \
        echo "Error: {{deb_file}} not found."; \
        echo "Run 'just fetch-release' to download the CI-built package from GitHub."; \
        exit 1; \
    fi
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{deb_file}}
    aptly -config=configs/aptly.conf publish update {{distribution}}
    @echo "Repository updated and published"

# Create aptly repository (run once)
repo-create repo_name="gentility-main":
    @echo "Creating aptly repository '{{repo_name}}'..."
    aptly -config=configs/aptly.conf repo create -distribution=stable -component=main {{repo_name}}
    @echo "Repository created"

# Show repository contents
repo-show repo_name="gentility-main":
    @echo "Repository '{{repo_name}}' contents:"
    aptly -config=configs/aptly.conf repo show -with-packages {{repo_name}}

# Initialize aptly database and GPG key (run once)
repo-init:
    @echo "Initializing aptly database and GPG key..."
    aptly -config=configs/aptly.conf db init || echo "Database already exists"
    @echo "Setting up GPG key for package signing..."
    ./scripts/setup-gpg.sh

# Setup GPG key for signing
setup-gpg:
    @echo "Setting up GPG key for package signing..."
    ./scripts/setup-gpg.sh

# Publish to local filesystem
repo-publish-local repo_name="gentility-main" distribution="stable":
    @echo "Publishing repository '{{repo_name}}' locally..."
    @if aptly -config=configs/aptly.conf publish list | grep -q "{{distribution}}"; then \
        echo "Repository already published, updating..."; \
        if [ -f .env ]; then \
            export $(cat .env | grep -v '^#' | xargs) && \
            aptly -config=configs/aptly.conf publish update -gpg-key="${GPG_KEY_ID}" {{distribution}} filesystem:local:debian; \
        else \
            aptly -config=configs/aptly.conf publish update -gpg-key=85C6BE5B453A071B {{distribution}} filesystem:local:debian; \
        fi; \
    else \
        echo "Publishing repository for first time..."; \
        if [ -f .env ]; then \
            export $(cat .env | grep -v '^#' | xargs) && \
            aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key="${GPG_KEY_ID}" {{repo_name}} filesystem:local:debian; \
        else \
            aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key=85C6BE5B453A071B {{repo_name}} filesystem:local:debian; \
        fi; \
    fi
    @echo "Repository published to ./public/"

# Publish to S3/DO Spaces
repo-publish-s3 repo_name="gentility-main" distribution="stable":
    @echo "Publishing repository '{{repo_name}}' to DO Spaces..."
    @if [ -f .env ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        AWS_ACCESS_KEY_ID="${DO_ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${DO_SECRET_KEY}" \
        aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key="${GPG_KEY_ID}" {{repo_name}} s3:do-spaces: && \
        just upload-gpg-key; \
    else \
        echo "Error: .env file not found. Please create it with DO_ACCESS_KEY and DO_SECRET_KEY"; \
        exit 1; \
    fi
    @echo "Repository published to DO Spaces"

# Update local published repository
repo-update-local repo_name="gentility-main" distribution="stable":
    @echo "Updating local repository with new package..."
    @if [ ! -f "{{deb_file}}" ]; then \
        echo "Error: {{deb_file}} not found."; \
        echo "Run 'just fetch-release' to download the CI-built package from GitHub."; \
        exit 1; \
    fi
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{deb_file}}
    aptly -config=configs/aptly.conf publish update -distribution={{distribution}} local:{{distribution}}
    @echo "Local repository updated"

# Update S3/DO Spaces published repository  
repo-update-s3 repo_name="gentility-main" distribution="stable":
    #!/bin/bash
    set -e
    echo "Updating DO Spaces repository with new package..."
    current_version=$(cat VERSION)
    deb_file="packages/{{binary_name}}_${current_version}_amd64.deb"
    
    if [ ! -f "$deb_file" ]; then
        echo "Error: Package file $deb_file not found!"
        exit 1
    fi
    
    aptly -config=configs/aptly.conf repo add {{repo_name}} "$deb_file"
    if [ -f .env ]; then
        export $(cat .env | grep -v '^#' | xargs)
        AWS_ACCESS_KEY_ID="${DO_ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${DO_SECRET_KEY}" \
        aptly -config=configs/aptly.conf publish update -gpg-key="${GPG_KEY_ID}" {{distribution}} s3:do-spaces:
        
        # Ensure GPG key is always available
        just upload-gpg-key
    else
        echo "Error: .env file not found. Please create it with DO_ACCESS_KEY and DO_SECRET_KEY"
        exit 1
    fi
    echo "DO Spaces repository updated"

# Upload GPG key to Digital Ocean Spaces root
upload-gpg-key:
    @echo "Uploading GPG key to DO Spaces..."
    @if [ -f .env ] && [ -f gentility-packages.gpg ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        AWS_ACCESS_KEY_ID="${DO_ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${DO_SECRET_KEY}" \
        aws s3 cp gentility-packages.gpg s3://gentility/gentility-packages.gpg --endpoint-url=https://sgp1.digitaloceanspaces.com --acl public-read; \
    else \
        echo "Error: .env file or gentility-packages.gpg not found"; \
        exit 1; \
    fi
    @echo "GPG key uploaded to https://gentility.sgp1.digitaloceanspaces.com/gentility-packages.gpg"

# Sync local repository to remote server via rsync
repo-sync-remote remote_path:
    @echo "Syncing local repository to remote server..."
    @echo "Target: {{remote_path}}"
    rsync -avz --delete ./public/ {{remote_path}}
    @echo "Repository synced to remote server"

# Complete release workflow (version, tag, and push)
release type="patch":
    #!/bin/bash
    set -e

    # Calculate what the new version will be
    current_version=$(cat VERSION)
    IFS='.' read -r major minor patch <<< "$current_version"

    if [ "{{type}}" = "major" ]; then
        new_version="$((major + 1)).0.0"
    elif [ "{{type}}" = "minor" ]; then
        new_version="$major.$((minor + 1)).0"
    else
        new_version="$major.$minor.$((patch + 1))"
    fi

    # Show release preview
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Release Preview"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "  Current version:  v${current_version}"
    echo "  New version:      v${new_version}"
    echo "  Release type:     {{type}}"
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo ""

    # Ask for confirmation
    read -p "Proceed with release? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "❌ Release cancelled"
        exit 1
    fi

    echo ""
    echo "🚀 Starting automated release workflow..."

    # Bump version
    just version-bump {{type}}

    # Get new version and validate consistency
    current_version=$(cat VERSION)
    echo "🔍 Validating version consistency..."

    # Check if all config files have consistent versions
    nfpm_version=$(grep "^version:" nfpm.yaml | sed 's/version: "\(.*\)"/\1/')
    nfpm_arm64_version=$(grep "^version:" nfpm-arm64.yaml | sed 's/version: "\(.*\)"/\1/')

    if [ "$current_version" != "$nfpm_version" ] || [ "$current_version" != "$nfpm_arm64_version" ]; then
        echo "❌ Version mismatch detected!"
        echo "  VERSION file: $current_version"
        echo "  nfpm.yaml: $nfpm_version"
        echo "  nfpm-arm64.yaml: $nfpm_arm64_version"
        echo "🔧 Auto-fixing version inconsistencies..."
        sed -i '' "s/version: \".*\"/version: \"$current_version\"/" nfpm.yaml nfpm-arm64.yaml
        echo "✅ Version files synchronized"
    fi

    echo ""
    echo "📝 Committing version changes..."
    # Stage only release-related files
    git add VERSION nfpm.yaml nfpm-arm64.yaml justfile Formula/gentility-agent.rb  README.md 2>/dev/null || true
    git commit -m "Release v${current_version}" || echo "No changes to commit"

    # Check if tag already exists
    if git tag -l "v${current_version}" | grep -q "v${current_version}"; then
        echo "⚠️  Tag v${current_version} already exists, removing it..."
        git tag -d "v${current_version}"
        git push origin --delete "v${current_version}" 2>/dev/null || echo "Tag not on remote"
    fi

    echo "🏷️  Creating git tag v${current_version}..."
    git tag "v${current_version}"

    echo "🚀 Pushing to GitHub..."
    git push origin master --tags

    echo ""
    echo "⏳ Waiting for GitHub Actions to register the workflow run..."
    sleep 5

    run_id=$(gh run list \
        --workflow=build.yml \
        --event=push \
        --branch="v${current_version}" \
        --limit=1 \
        --json databaseId \
        --jq '.[0].databaseId')

    if [ -z "$run_id" ]; then
        echo "⚠️  Could not find a workflow run for tag v${current_version}."
        echo "   Check https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions"
        echo "   and run 'just fetch-release' once the build finishes."
        exit 1
    fi

    echo "👀 Watching workflow run ${run_id}..."
    gh run watch "$run_id" --exit-status

    echo ""
    echo "📥 Fetching release artifacts..."
    just fetch-release

    echo ""
    echo "✅ Release v${current_version} completed successfully!"
    echo ""
    echo "📊 Release Summary:"
    echo "  Version: ${current_version}"
    echo "  Git tag: v${current_version}"
    echo "  Artifacts: ./packages/"
    echo ""
    echo "Next step: publish to the apt repo with 'just repo-update-s3'"

# Clean build artifacts
clean:
    @echo "Cleaning build artifacts..."
    rm -rf {{bin_dir}}
    rm -rf packages

# Run tests (if any exist)
test:
    @echo "Running tests..."
    crystal spec

# Quick development run
run-dev: build-dev
    @echo "Running development binary..."
    ./{{bin_dir}}/{{binary_name}} --debug

# Release binaries are built by GitHub Actions, so nfpm is no longer
# required locally — only crystal (dev), aptly (repo publishing), and
# gh (downloading release artifacts).
# Check that the tools this justfile needs are available
install-tools:
    @echo "Checking required tools..."
    @which crystal >/dev/null || (echo "Please install Crystal first: https://crystal-lang.org/install/"; exit 1)
    @which aptly >/dev/null || (echo "Please install aptly: brew install aptly  (or apt-get install aptly)"; exit 1)
    @which gh >/dev/null || (echo "Please install the GitHub CLI: https://cli.github.com/"; exit 1)
    @echo "✅ All required tools are available"

# Show current version
version:
    @echo "Current version: {{version}}"

# Bump version
version-bump type="patch":
    #!/bin/bash
    set -e

    current_version={{version}}
    IFS='.' read -r major minor patch <<< "$current_version"

    if [ "{{type}}" = "major" ]; then
        new_version="$((major + 1)).0.0"
    elif [ "{{type}}" = "minor" ]; then
        new_version="$major.$((minor + 1)).0"
    else
        new_version="$major.$minor.$((patch + 1))"
    fi

    echo "📝 Updating version from $current_version to $new_version"

    # Update VERSION file
    echo "$new_version" > VERSION
    echo "  ✅ Updated VERSION file"

    # Update nfpm configs
    sed -i '' "s/version: \"$current_version\"/version: \"$new_version\"/" nfpm.yaml nfpm-arm64.yaml 2>/dev/null || true
    echo "  ✅ Updated nfpm configs"

    # Update Homebrew formulas
    if [ -f "Formula/gentility-agent.rb" ]; then
        sed -i '' "s/tag: \"v$current_version\"/tag: \"v$new_version\"/" Formula/gentility-agent.rb
        echo "  ✅ Updated Homebrew formula"
    fi

    # Update README if it contains version references
    sed -i '' "s/gentility-agent_${current_version}_/gentility-agent_${new_version}_/g" README.md 2>/dev/null || true
    sed -i '' "s/download/v${current_version}/download\/v${new_version}/g" README.md 2>/dev/null || true

    echo ""
    echo "✅ Version bumped to $new_version"
    echo ""
    echo "Next steps:"
    echo "  1. Review the staged version changes"
    echo "  2. Commit and tag: just release-commit"

# Commit and tag after version bump
release-commit:
    #!/bin/bash
    set -e

    current_version={{version}}

    # Stage all version-related files
    git add VERSION nfpm.yaml nfpm-arm64.yaml Formula/gentility-agent.rb README.md 2>/dev/null || true

    # Commit
    git commit -m "Bump version to v${current_version}"

    # Create tag
    git tag "v${current_version}"

    echo "✅ Committed and tagged v${current_version}"
    echo ""
    echo "To push: git push origin master --tags"

# Show build information
info:
    @echo "Build Information:"
    @echo "  Binary name: {{binary_name}}"
    @echo "  Current version: {{version}}"
    @echo ""
    @echo "Available binaries:"
    @ls -lh {{bin_dir}}/{{binary_name}}-* 2>/dev/null || echo "  No binaries built yet"
    @echo ""
    @echo "Available packages:"
    @ls -lh packages/{{binary_name}}_{{version}}_*.deb 2>/dev/null || echo "  No packages built yet"

# Deploy packages with Ansible
deploy-packages: (repo-publish-local)
    @echo "Deploying packages to packages.gentility.ai..."
    @which ansible-playbook >/dev/null || (echo "Please install Ansible first: pip install ansible"; exit 1)
    ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/deploy-packages.yml

# Full S3 deployment workflow
deploy-s3: (repo-update-s3)
    @echo "S3 deployment complete!"
    @echo "Repository available at your S3 endpoint"

# Setup server with Ansible
setup-server:
    @echo "Setting up packages.gentility.ai server with Ansible..."
    @which ansible-playbook >/dev/null || (echo "Please install Ansible first: pip install ansible"; exit 1)
    ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/setup-server.yml

# Test repository locally
test-repo:
    @echo "Testing repository locally..."
    just repo-publish-local
    @echo "Starting local web server on http://localhost:8000"
    @echo "Test with: curl http://localhost:8000/debian/dists/stable/Release"
    @echo "Press Ctrl+C to stop"
    cd public && python3 -m http.server 8000

# Validate package signatures
validate-package:
    @echo "Validating package signatures..."
    cd public/debian && gpg --verify dists/stable/Release.gpg dists/stable/Release
    @echo "Package validation complete"
