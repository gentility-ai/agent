# Gentility AI Agent - Repository Deployment Guide

This guide walks you through setting up your own APT repository to distribute the Gentility AI agent via `apt-get install`.

## 🎯 Deployment Options

You have several options for hosting your repository:

1. **Self-hosted with nginx** (most control)
2. **Amazon S3** (scalable, CDN-friendly)
3. **GitHub Pages** (free for public repos)
4. **DigitalOcean Spaces, Cloudflare R2**, etc.

## 🔐 Prerequisites

1. **GPG Key** for package signing
2. **Domain name** for your repository (e.g., `packages.gentility.ai`)
3. **Server or hosting service**
4. **SSL certificate** (Let's Encrypt recommended)

## 📋 Quick Start

### 1. Initial Setup

```bash
# Install dependencies
just install-tools

# Initialize repository and GPG
just repo-init
just repo-create

# Build and package
just package
```

### 2. Choose Your Deployment Method

#### Option A: Self-Hosted with Nginx

```bash
# Publish locally first
just repo-publish-local

# Copy to your server
just repo-sync-remote user@your-server.com:/var/www/packages.gentility.ai/
```

#### Option B: Amazon S3

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export S3_BUCKET=your-bucket-name
export AWS_REGION=us-east-1

# Publish to S3
just repo-publish-s3
```

## 🌐 Self-Hosted Setup (Nginx)

### Server Setup

1. **Install Nginx and Certbot**:
   ```bash
   sudo apt update
   sudo apt install nginx certbot python3-certbot-nginx
   ```

2. **Create directory structure**:
   ```bash
   sudo mkdir -p /var/www/packages.gentility.ai
   sudo chown $USER:www-data /var/www/packages.gentility.ai
   sudo chmod 755 /var/www/packages.gentility.ai
   ```

3. **Configure Nginx**:
   ```bash
   sudo cp configs/nginx-repo.conf /etc/nginx/sites-available/packages.gentility.ai
   sudo ln -s /etc/nginx/sites-available/packages.gentility.ai /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. **Get SSL certificate**:
   ```bash
   sudo certbot --nginx -d packages.gentility.ai
   ```

5. **Copy repository files**:
   ```bash
   just repo-publish-local
   rsync -avz --delete ./public/ user@your-server:/var/www/packages.gentility.ai/
   
   # Copy the landing page
   scp configs/index.html user@your-server:/var/www/packages.gentility.ai/
   
   # Copy GPG public key
   scp gentility-packages.gpg user@your-server:/var/www/packages.gentility.ai/
   ```

## ☁️ Amazon S3 Setup

### Prerequisites

1. **AWS Account** with S3 access
2. **S3 Bucket** configured for static website hosting
3. **CloudFront** distribution (recommended)
4. **Route 53** or DNS provider for custom domain

### Setup Steps

1. **Create S3 bucket**:
   ```bash
   aws s3 mb s3://gentility-packages --region us-east-1
   ```

2. **Configure bucket for public read**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "PublicReadGetObject",
         "Effect": "Allow",
         "Principal": "*",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::gentility-packages/*"
       }
     ]
   }
   ```

3. **Enable static website hosting**:
   ```bash
   aws s3 website s3://gentility-packages --index-document index.html
   ```

4. **Update aptly configuration**:
   ```bash
   # Edit configs/aptly-s3.conf with your bucket details
   export S3_BUCKET=gentility-packages
   export AWS_REGION=us-east-1
   ```

5. **Publish to S3**:
   ```bash
   just repo-publish-s3
   ```

## 🔄 Continuous Deployment

### GitHub Actions Workflow

Create `.github/workflows/release.yml`:

```yaml
name: Build and Deploy Package

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Crystal
        uses: crystal-lang/install-crystal@v1
      
      - name: Install Just
        run: |
          curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin
          
      - name: Install nfpm
        run: |
          curl -sfL https://install.goreleaser.com/github.com/goreleaser/nfpm.sh | sh -s -- -b /usr/local/bin
          
      - name: Install aptly
        run: |
          sudo apt-get update
          sudo apt-get install aptly
          
      - name: Import GPG key
        run: |
          echo "${{ secrets.GPG_PRIVATE_KEY }}" | gpg --batch --import
          
      - name: Build and deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          just repo-init
          just repo-create
          just repo-update-s3
```

## 📦 Package Updates

### Version Management

Version is stored in `VERSION` file. The agent reads this at compile time.

### Quick Release

```bash
# Complete release (bump version, build, deploy, tag, push)
just release patch  # or minor/major
```

### Manual Release Steps

```bash
# 1. Bump version (updates VERSION file and all references)
just version-bump patch  # or minor/major

# 2. Build and package
just package-amd64

# 3. Update repository
just repo-update-local  # or repo-update-s3

# 4. Commit and tag
git add -A
git commit -m "Release v$(cat VERSION)"
git tag "v$(cat VERSION)"
git push origin master --tags

# 5. Sync to server (if self-hosted)
just repo-sync-remote user@your-server:/var/www/packages.gentility.ai/
```

## 👥 User Installation

Once your repository is set up, users can install with:

```bash
# Add repository key
curl -s https://packages.gentility.ai/gentility-packages.gpg | sudo apt-key add -

# Add repository
echo "deb https://packages.gentility.ai/debian stable main" | sudo tee /etc/apt/sources.list.d/gentility.list

# Install
sudo apt update
sudo apt install gentility-agent
```

## 🔧 Troubleshooting

### Common Issues

1. **GPG signature verification failed**
   - Ensure GPG key is properly imported on user systems
   - Check that packages are signed correctly

2. **404 errors**
   - Verify nginx configuration and file permissions
   - Check that repository structure is correct

3. **S3 access denied**
   - Verify bucket policy allows public read access
   - Check AWS credentials and permissions

### Debugging Commands

```bash
# Check repository structure
just repo-show

# Verify GPG signatures
gpg --verify Release.gpg Release

# Test repository locally
python3 -m http.server 8000
# Then try: apt-get update with local repository
```

## 📊 Monitoring

### Nginx Logs
```bash
# Access logs
tail -f /var/log/nginx/packages.gentility.ai.access.log

# Error logs  
tail -f /var/log/nginx/packages.gentility.ai.error.log
```

### S3 Metrics
- Use CloudWatch to monitor S3 request metrics
- Set up alerts for unusual traffic patterns

## 🔒 Security Best Practices

1. **Use HTTPS** everywhere
2. **Keep GPG keys secure** - store private keys safely
3. **Regular updates** - keep server and packages updated
4. **Access logs** - monitor for suspicious activity
5. **Backup** repository and keys regularly

## 📈 Scaling

For high-traffic scenarios:

1. **Use CDN** (CloudFront, Cloudflare)
2. **Multiple mirrors** across regions  
3. **Load balancing** for self-hosted
4. **Caching strategies** at nginx/CDN level

## 💡 Tips

- Test repository with a VM before going live
- Keep old package versions for rollback capability
- Document your deployment process for team members
- Consider automated security scanning of packages
- Set up monitoring and alerting for repository availability