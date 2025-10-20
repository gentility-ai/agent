require "base58"
require "openssl"
require "base64"
require "json"
require "yaml"
require "ed25519"

# Cryptographic utilities for Ed25519 keypairs and credential encryption
module AgentCrypto
  # Parse an Ed25519 private key from base58 string and return signing key
  def self.parse_private_key(base58_key : String) : Ed25519::SigningKey
    key_bytes = Base58.decode(base58_key).to_slice

    # Validate key length before creating SigningKey
    if key_bytes.size != 32
      raise Ed25519::VerifyError.new("Expected 32 bytes. Key is only #{key_bytes.size} bytes")
    end

    Ed25519::SigningKey.new(key_bytes)
  end

  # Get public key from private key as base58 string
  def self.public_key_base58(signing_key : Ed25519::SigningKey) : String
    verify_key = signing_key.verify_key
    Base58.encode(verify_key.key_bytes)
  end

  # Derive AES-256 key from Ed25519 private key
  # Uses first 32 bytes of the signing key as AES key
  def self.derive_aes_key(signing_key : Ed25519::SigningKey) : Bytes
    # Ed25519 private key is 32 bytes, perfect for AES-256
    signing_key.key_bytes
  end

  # Encrypt data with AES-256-CBC using the signing key
  def self.encrypt(signing_key : Ed25519::SigningKey, plaintext : String) : String
    aes_key = derive_aes_key(signing_key)

    # Generate random IV
    iv = Random::Secure.random_bytes(16)

    # Create cipher
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.key = aes_key
    cipher.iv = iv

    # Encrypt
    encrypted = IO::Memory.new
    encrypted.write(iv) # Prepend IV to ciphertext
    encrypted.write(cipher.update(plaintext))
    encrypted.write(cipher.final)

    # Return base64 encoded result
    Base64.strict_encode(encrypted.to_slice)
  end

  # Decrypt data with AES-256-CBC using the signing key
  def self.decrypt(signing_key : Ed25519::SigningKey, ciphertext_b64 : String) : String
    aes_key = derive_aes_key(signing_key)

    # Decode base64
    ciphertext = Base64.decode(ciphertext_b64)

    # Extract IV (first 16 bytes)
    iv = ciphertext[0, 16]
    encrypted_data = ciphertext[16..-1]

    # Create cipher
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.decrypt
    cipher.key = aes_key
    cipher.iv = iv

    # Decrypt
    decrypted = IO::Memory.new
    decrypted.write(cipher.update(encrypted_data))
    decrypted.write(cipher.final)

    String.new(decrypted.to_slice)
  end

  # Store encrypted credentials in config file
  def self.store_credentials(config_file : String, db_target_id : String, credentials : String, signing_key : Ed25519::SigningKey)
    # Encrypt credentials
    encrypted = encrypt(signing_key, credentials)

    # Load config
    config = if File.exists?(config_file)
               YAML.parse(File.read(config_file))
             else
               YAML.parse("{}")
             end

    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    # Get or create encrypted_db_credentials section
    creds_section = if existing = config_hash[YAML::Any.new("encrypted_db_credentials")]?
                      existing.as_h? || {} of YAML::Any => YAML::Any
                    else
                      {} of YAML::Any => YAML::Any
                    end

    # Store encrypted credentials
    creds_section[YAML::Any.new(db_target_id)] = YAML::Any.new(encrypted)
    config_hash[YAML::Any.new("encrypted_db_credentials")] = YAML::Any.new(creds_section)

    # Write back to file
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o600)
  end

  # Load and decrypt credentials from config file
  def self.load_credentials(config_file : String, db_target_id : String, signing_key : Ed25519::SigningKey, silent : Bool = false) : String?
    return nil unless File.exists?(config_file)

    config = YAML.parse(File.read(config_file))
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    creds_section = config_hash[YAML::Any.new("encrypted_db_credentials")]?
    return nil unless creds_section

    creds_hash = creds_section.as_h? || {} of YAML::Any => YAML::Any
    encrypted = creds_hash[YAML::Any.new(db_target_id)]?
    return nil unless encrypted

    encrypted_str = encrypted.as_s? || return nil
    decrypt(signing_key, encrypted_str)
  rescue ex
    puts "Warning: Failed to load credentials for #{db_target_id}: #{ex.message}" unless silent
    nil
  end

  # Convert Ed25519 seed to X25519 keypair
  # Returns {private_key, public_key} as 32-byte Bytes
  def self.ed25519_seed_to_x25519_keypair(ed25519_seed : Bytes) : {Bytes, Bytes}
    raise "Ed25519 seed must be 32 bytes" unless ed25519_seed.size == 32

    # Use ed25519 shard's built-in methods
    # The seed is already in the right format for X25519
    # For X25519, we use the seed directly as the private key (after clamping)
    x25519_private = ed25519_seed.dup
    Ed25519.adjust_bytes_25519(x25519_private)

    # Derive public key using curve25519 scalar multiplication with base point
    x25519_public = Ed25519::Curve25519.scalar_mult_base(x25519_private)

    {x25519_private, x25519_public}
  end

  # Perform X25519 ECDH to derive shared secret
  # Returns 32-byte shared secret
  def self.x25519_ecdh(my_private_key : Bytes, their_public_key : Bytes) : Bytes
    raise "X25519 private key must be 32 bytes" unless my_private_key.size == 32
    raise "X25519 public key must be 32 bytes" unless their_public_key.size == 32

    # Use ed25519 shard's Curve25519 scalar multiplication
    # shared_secret = my_private_key * their_public_key
    Ed25519::Curve25519.scalar_mult(my_private_key, their_public_key)
  end

  # Decrypt credentials encrypted with AES-256-CBC using shared secret
  # encrypted_payload should be base64(iv + ciphertext)
  # The IV is the first 16 bytes, followed by the ciphertext
  def self.decrypt_with_shared_secret(shared_secret : Bytes, encrypted_payload : String) : String
    raise "Shared secret must be 32 bytes" unless shared_secret.size == 32

    # Decode base64 input
    payload = Base64.decode(encrypted_payload)

    # Validate size (must have at least IV)
    raise "Encrypted payload must include at least 16 bytes for IV" unless payload.size >= 16

    # Split payload into IV (first 16 bytes) and ciphertext
    iv = payload[0, 16]
    ciphertext = payload[16..-1]

    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.decrypt
    cipher.key = shared_secret
    cipher.iv = iv

    # Decrypt ciphertext
    decrypted = IO::Memory.new
    decrypted.write(cipher.update(ciphertext))
    decrypted.write(cipher.final)

    String.new(decrypted.to_slice)
  end
end
