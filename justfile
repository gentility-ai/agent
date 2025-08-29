# Gentility AI Agent - Build and Packaging with Just

binary_name := "gentility-agent"
bin_dir := "bin"
# Default to amd64 for production deployments
arch := env_var_or_default("TARGET_ARCH", "amd64")

# Get current source hash (excluding the VERSION line to avoid feedback loop)
current_hash := `grep -v 'VERSION = ' src/agent.cr | shasum -a 256 | cut -d' ' -f1`
lockfile_version := `cat .version-lock.json 2>/dev/null | jq -r '.current_version // "1.0.0"' 2>/dev/null || echo "1.0.0"`
lockfile_hash := `cat .version-lock.json 2>/dev/null | jq -r '.source_hash // ""' 2>/dev/null || echo ""`

version := lockfile_version
deb_file := binary_name + "_" + version + "_" + arch + ".deb"

# Show available commands
default:
    @just --list

# Install Crystal dependencies
install-deps:
    @echo "Installing Crystal dependencies..."
    shards install

# Build the Crystal binary for Linux (static when possible)
build: install-deps
    @echo "Building {{binary_name}} v{{version}} for {{arch}}..."
    @mkdir -p {{bin_dir}}
    @if [ "$(uname)" = "Linux" ]; then \
        crystal build src/agent.cr --release --static --no-debug -o {{bin_dir}}/{{binary_name}}; \
    else \
        echo "WARNING: Building on macOS - binary will be for native architecture"; \
        echo "For Linux deployment, use 'just build-linux-amd64' instead"; \
        crystal build src/agent.cr --release --no-debug -o {{bin_dir}}/{{binary_name}}; \
    fi
    @echo "Binary built: {{bin_dir}}/{{binary_name}}"

# Build for current platform (development)
build-dev: install-deps
    @echo "Building {{binary_name}} v{{version}} for development..."
    @mkdir -p {{bin_dir}}
    crystal build src/agent.cr -o {{bin_dir}}/{{binary_name}}
    @echo "Development binary built: {{bin_dir}}/{{binary_name}}"

# Build on remote Linux machine (core7) for AMD64
build-remote-amd64:
    @echo "Building {{binary_name}} v{{version}} on remote Linux machine (core7) for AMD64..."
    @if [ -f .env ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        echo "Syncing source to ${CORE7_USER}@${CORE7_IP}..." && \
        rsync -avz --exclude 'bin/' --exclude '*.deb' --exclude 'aptly-repo/' --exclude 'public/' --exclude '.git/' ./ ${CORE7_USER}@${CORE7_IP}:/tmp/gentility-build/ && \
        echo "Building on core7..." && \
        ssh ${CORE7_USER}@${CORE7_IP} "cd /tmp/gentility-build && mkdir -p bin && shards install && crystal build src/agent.cr --release --static --no-debug -o bin/{{binary_name}}-{{version}}-linux-amd64" && \
        echo "Fetching AMD64 binary from core7..." && \
        mkdir -p {{bin_dir}} && \
        scp ${CORE7_USER}@${CORE7_IP}:/tmp/gentility-build/bin/{{binary_name}}-{{version}}-linux-amd64 {{bin_dir}}/{{binary_name}}-{{version}}-linux-amd64 && \
        echo "Linux AMD64 binary fetched: {{bin_dir}}/{{binary_name}}-{{version}}-linux-amd64"; \
    else \
        echo "Error: .env file not found. Please create it with CORE7_IP and CORE7_USER"; \
        exit 1; \
    fi

# Build locally for ARM64 (Mac M1) - Note: This will be Darwin ARM64, not Linux ARM64
build-local-arm64: install-deps
    @echo "Building {{binary_name}} v{{version}} locally for Darwin ARM64..."
    @mkdir -p {{bin_dir}}
    crystal build src/agent.cr --release --no-debug -o {{bin_dir}}/{{binary_name}}-{{version}}-darwin-arm64
    @echo "Darwin ARM64 binary built: {{bin_dir}}/{{binary_name}}-{{version}}-darwin-arm64"

# Create DEB package for AMD64 (with automatic version management)
package-amd64: version-update build-remote-amd64
    @echo "Creating DEB package for AMD64..."
    @if [ -f "{{binary_name}}_{{version}}_amd64.deb" ]; then \
        echo "⚠️  Package {{binary_name}}_{{version}}_amd64.deb already exists!"; \
        echo "Removing existing package to rebuild with latest changes..."; \
        rm -f {{binary_name}}_{{version}}_amd64.deb; \
    fi
    @cp {{bin_dir}}/{{binary_name}}-{{version}}-linux-amd64 {{bin_dir}}/{{binary_name}}
    nfpm pkg --packager deb --config nfpm.yaml --target {{binary_name}}_{{version}}_amd64.deb
    @rm {{bin_dir}}/{{binary_name}}
    @echo "✅ DEB package created: {{binary_name}}_{{version}}_amd64.deb"

# Create DEB package for ARM64 (requires Linux ARM64 build)
package-arm64:
    @echo "Creating DEB package for ARM64..."
    @echo "ERROR: Linux ARM64 build not yet implemented. You'll need to build on a Linux ARM64 machine."
    @exit 1

# Package all architectures
package-all: package-amd64
    @echo "All available packages created"

# Legacy package command (defaults to AMD64)
package: package-amd64

# Add specific package to aptly repository
repo-add-package package_file repo_name="gentility-main":
    @echo "Adding {{package_file}} to aptly repository '{{repo_name}}'..."
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{package_file}}
    @echo "Package added to repository"

# Add AMD64 package to aptly repository
repo-add-amd64 repo_name="gentility-main": package-amd64
    @echo "Adding AMD64 package to aptly repository '{{repo_name}}'..."
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{binary_name}}_{{version}}_amd64.deb
    @echo "AMD64 package added to repository"

# Add all available packages to repository
repo-add-all repo_name="gentility-main": package-all
    @echo "Adding all packages to repository..."
    @for pkg in {{binary_name}}_{{version}}_*.deb; do \
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
repo-update repo_name="gentility-main" distribution="stable": package
    @echo "Updating repository with new package..."
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
    @if [ -f .env ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key="${GPG_KEY_ID}" {{repo_name}} filesystem:local:debian; \
    else \
        aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key=85C6BE5B453A071B {{repo_name}} filesystem:local:debian; \
    fi
    @echo "Repository published to ./public/"

# Publish to S3/DO Spaces
repo-publish-s3 repo_name="gentility-main" distribution="stable":
    @echo "Publishing repository '{{repo_name}}' to DO Spaces..."
    @if [ -f .env ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        AWS_ACCESS_KEY_ID="${DO_ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${DO_SECRET_KEY}" \
        aptly -config=configs/aptly.conf publish repo -distribution={{distribution}} -gpg-key="${GPG_KEY_ID}" {{repo_name}} s3:do-spaces:; \
    else \
        echo "Error: .env file not found. Please create it with DO_ACCESS_KEY and DO_SECRET_KEY"; \
        exit 1; \
    fi
    @echo "Repository published to DO Spaces"

# Update local published repository
repo-update-local repo_name="gentility-main" distribution="stable": package
    @echo "Updating local repository with new package..."
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{deb_file}}
    aptly -config=configs/aptly.conf publish update -distribution={{distribution}} local:{{distribution}}
    @echo "Local repository updated"

# Update S3/DO Spaces published repository
repo-update-s3 repo_name="gentility-main" distribution="stable": package
    @echo "Updating DO Spaces repository with new package..."
    aptly -config=configs/aptly.conf repo add {{repo_name}} {{deb_file}}
    @if [ -f .env ]; then \
        export $(cat .env | grep -v '^#' | xargs) && \
        AWS_ACCESS_KEY_ID="${DO_ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${DO_SECRET_KEY}" \
        aptly -config=configs/aptly.conf publish update -gpg-key="${GPG_KEY_ID}" {{distribution}} s3:do-spaces:; \
    else \
        echo "Error: .env file not found. Please create it with DO_ACCESS_KEY and DO_SECRET_KEY"; \
        exit 1; \
    fi
    @echo "DO Spaces repository updated"

# Sync local repository to remote server via rsync
repo-sync-remote remote_path:
    @echo "Syncing local repository to remote server..."
    @echo "Target: {{remote_path}}"
    rsync -avz --delete ./public/ {{remote_path}}
    @echo "Repository synced to remote server"

# Complete release workflow (build, package, and publish)
release type="patch":
    @echo "🚀 Starting automated release workflow..."
    @just version-check
    @echo ""
    @echo "📦 Building and packaging..."
    @just package-amd64
    @echo ""
    @echo "📤 Updating repository..."
    @just repo-update-s3
    @echo ""
    @echo "✅ Release v{{version}} completed successfully!"
    @echo ""
    @echo "📊 Release Summary:"
    @echo "  Version: {{version}}"
    @echo "  Package: {{binary_name}}_{{version}}_amd64.deb"
    @echo "  Repository: https://gentility.sgp1.digitaloceanspaces.com/debian/"

# Legacy release command (renamed to avoid conflict)
release-legacy repo_name="gentility-main" distribution="stable": package (repo-update repo_name distribution)
    @echo "Full release completed!"

# Clean build artifacts
clean:
    @echo "Cleaning build artifacts..."
    rm -rf {{bin_dir}}
    rm -f *.deb
    rm -f *.rpm

# Run tests (if any exist)
test:
    @echo "Running tests..."
    crystal spec

# Quick development run
run-dev: build-dev
    @echo "Running development binary..."
    ./{{bin_dir}}/{{binary_name}} --debug

# Install required tools
install-tools:
    @echo "Checking and installing required tools..."
    @which crystal >/dev/null || (echo "Please install Crystal first: https://crystal-lang.org/install/"; exit 1)
    @which nfpm >/dev/null || (echo "Installing nfpm..." && curl -sfL https://install.goreleaser.com/github.com/goreleaser/nfpm.sh | sh -s -- -b ~/.local/bin)
    @which aptly >/dev/null || (echo "Please install aptly: apt-get install aptly"; exit 1)

# Check version status and update if source changed
version-check:
    @echo "Version Status:"
    @echo "  Current version: {{version}}"
    @echo "  Current source hash: {{current_hash}}"
    @echo "  Lockfile hash: {{lockfile_hash}}"
    @if [ "{{current_hash}}" != "{{lockfile_hash}}" ]; then \
        echo "  🔄 Source has changed - version needs to be updated"; \
        echo "  Run 'just version-update' to increment version"; \
    else \
        echo "  ✅ Version {{version}} is up to date with source"; \
    fi

# Update version automatically when source changes
version-update type="patch":
    @echo "Checking if version update is needed..."
    @if [ "{{current_hash}}" = "{{lockfile_hash}}" ]; then \
        echo "  ✅ Source hasn't changed, no version update needed"; \
        exit 0; \
    fi
    @echo "  🔄 Source has changed, incrementing version..."
    @current_version={{version}}; \
    IFS='.' read -r major minor patch <<< "$current_version"; \
    if [ "{{type}}" = "major" ]; then \
        new_version="$((major + 1)).0.0"; \
    elif [ "{{type}}" = "minor" ]; then \
        new_version="$major.$((minor + 1)).0"; \
    else \
        new_version="$major.$minor.$((patch + 1))"; \
    fi; \
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); \
    echo "  📝 Updating version from $current_version to $new_version"; \
    sed -i '' "s/VERSION = \"$current_version\"/VERSION = \"$new_version\"/" src/agent.cr; \
    sed -i '' "s/version: \"$current_version\"/version: \"$new_version\"/" nfpm.yaml nfpm-arm64.yaml 2>/dev/null || true; \
    old_entry=$(cat .version-lock.json 2>/dev/null | jq -c '{version: .current_version, hash: .source_hash, timestamp: .last_updated}' 2>/dev/null || echo '{}'); \
    cat .version-lock.json 2>/dev/null | jq --arg version "$$new_version" --arg hash "{{current_hash}}" --arg timestamp "$$timestamp" --argjson old "$$old_entry" \
        '.current_version = $version | .source_hash = $hash | .last_updated = $timestamp | .history = ((.history // []) + [$old])[-10:]' > .version-lock.json.tmp && mv .version-lock.json.tmp .version-lock.json || \
    echo "{\"current_version\": \"$new_version\", \"source_hash\": \"{{current_hash}}\", \"last_updated\": \"$timestamp\", \"history\": []}" | jq . > .version-lock.json; \
    echo "  ✅ Version updated to $new_version and lockfile saved"

# Force version bump (manual override)
version-bump type="patch":
    @echo "Manually bumping version ({{type}})..."
    @current_version={{version}}; \
    IFS='.' read -r major minor patch <<< "$current_version"; \
    if [ "{{type}}" = "major" ]; then \
        new_version="$((major + 1)).0.0"; \
    elif [ "{{type}}" = "minor" ]; then \
        new_version="$major.$((minor + 1)).0"; \
    else \
        new_version="$major.$minor.$((patch + 1))"; \
    fi; \
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); \
    echo "  📝 Updating version from $current_version to $new_version"; \
    sed -i '' "s/VERSION = \"$current_version\"/VERSION = \"$new_version\"/" src/agent.cr; \
    sed -i '' "s/version: \"$current_version\"/version: \"$new_version\"/" nfpm.yaml nfpm-arm64.yaml 2>/dev/null || true; \
    old_entry=$(cat .version-lock.json 2>/dev/null | jq -c '{version: .current_version, hash: .source_hash, timestamp: .last_updated}' 2>/dev/null || echo '{}'); \
    cat .version-lock.json 2>/dev/null | jq --arg version "$$new_version" --arg hash "{{current_hash}}" --arg timestamp "$$timestamp" --argjson old "$$old_entry" \
        '.current_version = $version | .source_hash = $hash | .last_updated = $timestamp | .history = ((.history // []) + [$old])[-10:]' > .version-lock.json.tmp && mv .version-lock.json.tmp .version-lock.json || \
    echo "{\"current_version\": \"$new_version\", \"source_hash\": \"{{current_hash}}\", \"last_updated\": \"$timestamp\", \"history\": []}" | jq . > .version-lock.json; \
    echo "  ✅ Version bumped to $new_version"

# Show build information
info:
    @echo "Build Information:"
    @echo "  Binary name: {{binary_name}}"
    @echo "  Current version: {{version}}"
    @echo "  Source hash: {{current_hash}}"
    @echo "  Lockfile hash: {{lockfile_hash}}"
    @if [ "{{current_hash}}" != "{{lockfile_hash}}" ]; then \
        echo "  Status: 🔄 Source changed, version will be updated on next build"; \
    else \
        echo "  Status: ✅ Up to date"; \
    fi
    @echo ""
    @echo "Available binaries:"
    @ls -lh {{bin_dir}}/{{binary_name}}-* 2>/dev/null || echo "  No binaries built yet"
    @echo ""
    @echo "Available packages:"
    @ls -lh {{binary_name}}_{{version}}_*.deb 2>/dev/null || echo "  No packages built yet"

# Deploy to self-hosted server
deploy-nginx remote_path: (repo-publish-local)
    @echo "Deploying to nginx server..."
    rsync -avz --delete ./public/ {{remote_path}}
    rsync -avz ./configs/index.html {{remote_path}}
    rsync -avz ./gentility-packages.gpg {{remote_path}}
    @echo "Deployment complete!"
    @echo "Repository available at: {{remote_path}}"

# Full S3 deployment workflow
deploy-s3: (repo-update-s3)
    @echo "S3 deployment complete!"
    @echo "Repository available at your S3 endpoint"

# Setup server (run this on your server)
setup-server domain:
    @echo "Setting up server for {{domain}}..."
    sudo mkdir -p /var/www/{{domain}}
    sudo chown $(whoami):www-data /var/www/{{domain}}
    sudo chmod 755 /var/www/{{domain}}
    @echo "Install nginx and certbot:"
    @echo "  sudo apt install nginx certbot python3-certbot-nginx"
    @echo "Configure nginx:"
    @echo "  sudo cp configs/nginx-repo.conf /etc/nginx/sites-available/{{domain}}"
    @echo "  sudo ln -s /etc/nginx/sites-available/{{domain}} /etc/nginx/sites-enabled/"
    @echo "  sudo nginx -t && sudo systemctl reload nginx"
    @echo "Get SSL certificate:"
    @echo "  sudo certbot --nginx -d {{domain}}"

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