#!/bin/bash

# GPG Key Setup for Repository Signing
# Run this once to set up package signing

set -e

echo "Setting up GPG key for Gentility AI package signing..."

# Check if GPG key already exists
if gpg --list-secret-keys --keyid-format=long | grep -q "Gentility AI"; then
    echo "GPG key for Gentility AI already exists."
    gpg --list-secret-keys --keyid-format=long | grep -A1 "Gentility AI"
    exit 0
fi

echo "Creating GPG key configuration..."
cat > /tmp/gpg-batch <<EOF
%echo Generating GPG key for Gentility AI package signing
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Gentility AI Package Signing
Name-Comment: Automated package signing key
Name-Email: packages@gentility.ai
Expire-Date: 2y
%no-protection
%commit
%echo Done
EOF

echo "Generating GPG key (this may take a while)..."
gpg --batch --generate-key /tmp/gpg-batch

# Clean up temp file
rm /tmp/gpg-batch

# Get the key ID (looking for the most recent key with our email)
KEY_ID=$(gpg --list-secret-keys --keyid-format=long packages@gentility.ai 2>/dev/null | grep "^sec" | cut -d'/' -f2 | cut -d' ' -f1)

echo ""
echo "✅ GPG key created successfully!"
echo "Key ID: $KEY_ID"
echo ""
echo "Export the public key to share with users:"
echo "  gpg --armor --export $KEY_ID > gentility-packages.gpg"
echo ""
echo "Users will add your key with:"
echo "  curl -s https://your-domain.com/gentility-packages.gpg | sudo apt-key add -"
echo ""

# Export the public key
gpg --armor --export $KEY_ID > gentility-packages.gpg
echo "Public key exported to: gentility-packages.gpg"

# Set the signing key for aptly
echo "Configuring aptly to use this key..."
echo "Add this to your aptly config or set environment variable:"
echo "export GPG_KEY_ID=$KEY_ID"