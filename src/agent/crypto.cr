require "base58"
require "openssl"
require "base64"
require "json"
require "yaml"
require "ed25519"
require "uuid"
require "uri"

# Credential metadata for local storage
struct CredentialMeta
  include JSON::Serializable

  property name : String
  property uuid : String
  property type : String # "postgres" or "mysql"
  property host : String
  property port : Int32
  property database : String

  def initialize(@name, @uuid, @type, @host, @port, @database)
  end

  # For server advertisement (no sensitive data)
  def to_advertisement
    {"name" => name, "uuid" => uuid, "type" => type, "host" => host}
  end
end

# Parsed connection URL result
struct ParsedConnectionURL
  property type : String # "postgres" or "mysql"
  property host : String
  property port : Int32
  property database : String
  property username : String?
  property password : String?

  def initialize(@type, @host, @port, @database, @username, @password)
  end

  # Parse a database connection URL
  # Supports: postgres://user:pass@host:port/database
  #           mysql://user:pass@host:port/database
  #           postgresql://... (alias for postgres)
  def self.parse(url : String) : ParsedConnectionURL
    uri = URI.parse(url)

    # Determine type from scheme
    type = case uri.scheme
           when "postgres", "postgresql" then "postgres"
           when "mysql", "mariadb"       then "mysql"
           else
             raise "Unsupported database type: #{uri.scheme}. Use postgres:// or mysql://"
           end

    # Default ports
    default_port = type == "postgres" ? 5432 : 3306

    host = uri.host || raise "Missing host in connection URL"
    port = uri.port || default_port
    database = uri.path.try(&.lstrip('/')) || ""
    raise "Missing database name in connection URL" if database.empty?

    # URL decode username/password
    username = uri.user.try { |u| URI.decode(u) }
    password = uri.password.try { |p| URI.decode(p) }

    ParsedConnectionURL.new(type, host, port, database, username, password)
  end
end

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
    File.chmod(config_file, 0o640)
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

  # Generate a new UUID for credential identification
  def self.generate_uuid : String
    UUID.random.to_s
  end

  # Store credential with metadata (friendly name mapping)
  # Stores metadata in db_credentials_meta and encrypted secrets in encrypted_db_credentials
  def self.store_credential_with_meta(config_file : String, meta : CredentialMeta, username : String, password : String, signing_key : Ed25519::SigningKey)
    # Load config
    config = if File.exists?(config_file)
               YAML.parse(File.read(config_file))
             else
               YAML.parse("{}")
             end

    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    # Get or create db_credentials_meta section
    meta_section = if existing = config_hash[YAML::Any.new("db_credentials_meta")]?
                     existing.as_h? || {} of YAML::Any => YAML::Any
                   else
                     {} of YAML::Any => YAML::Any
                   end

    # Store metadata by friendly name
    meta_hash = {
      YAML::Any.new("uuid")     => YAML::Any.new(meta.uuid),
      YAML::Any.new("type")     => YAML::Any.new(meta.type),
      YAML::Any.new("host")     => YAML::Any.new(meta.host),
      YAML::Any.new("port")     => YAML::Any.new(meta.port.to_i64),
      YAML::Any.new("database") => YAML::Any.new(meta.database),
    }
    meta_section[YAML::Any.new(meta.name)] = YAML::Any.new(meta_hash)
    config_hash[YAML::Any.new("db_credentials_meta")] = YAML::Any.new(meta_section)

    # Store encrypted credentials (includes all connection details for query execution)
    secrets = {
      "username" => username,
      "password" => password,
      "host"     => meta.host,
      "port"     => meta.port,
      "database" => meta.database,
      "type"     => meta.type,
    }.to_json
    encrypted = encrypt(signing_key, secrets)

    # Get or create encrypted_db_credentials section
    creds_section = if existing = config_hash[YAML::Any.new("encrypted_db_credentials")]?
                      existing.as_h? || {} of YAML::Any => YAML::Any
                    else
                      {} of YAML::Any => YAML::Any
                    end

    creds_section[YAML::Any.new(meta.uuid)] = YAML::Any.new(encrypted)
    config_hash[YAML::Any.new("encrypted_db_credentials")] = YAML::Any.new(creds_section)

    # Write back to file
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o640)
  end

  # Load credential metadata by friendly name
  def self.load_credential_meta(config_file : String, name : String) : CredentialMeta?
    return nil unless File.exists?(config_file)

    config = YAML.parse(File.read(config_file))
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    meta_section = config_hash[YAML::Any.new("db_credentials_meta")]?
    return nil unless meta_section

    meta_hash = meta_section.as_h? || {} of YAML::Any => YAML::Any
    meta_entry = meta_hash[YAML::Any.new(name)]?
    return nil unless meta_entry

    entry = meta_entry.as_h?
    return nil unless entry

    uuid = entry[YAML::Any.new("uuid")]?.try(&.as_s)
    type = entry[YAML::Any.new("type")]?.try(&.as_s)
    host = entry[YAML::Any.new("host")]?.try(&.as_s)
    port = entry[YAML::Any.new("port")]?.try(&.as_i)
    database = entry[YAML::Any.new("database")]?.try(&.as_s)

    return nil unless uuid && type && host && port && database

    CredentialMeta.new(name, uuid, type, host, port, database)
  rescue
    nil
  end

  # List all credential metadata
  def self.list_credentials_meta(config_file : String) : Array(CredentialMeta)
    result = [] of CredentialMeta
    return result unless File.exists?(config_file)

    config = YAML.parse(File.read(config_file))
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    meta_section = config_hash[YAML::Any.new("db_credentials_meta")]?
    return result unless meta_section

    meta_hash = meta_section.as_h? || {} of YAML::Any => YAML::Any
    meta_hash.each do |name_any, entry_any|
      name = name_any.as_s? || next
      entry = entry_any.as_h? || next

      uuid = entry[YAML::Any.new("uuid")]?.try(&.as_s) || next
      type = entry[YAML::Any.new("type")]?.try(&.as_s) || next
      host = entry[YAML::Any.new("host")]?.try(&.as_s) || next
      port = entry[YAML::Any.new("port")]?.try(&.as_i) || next
      database = entry[YAML::Any.new("database")]?.try(&.as_s) || next

      result << CredentialMeta.new(name, uuid, type, host, port, database)
    end

    result
  rescue
    [] of CredentialMeta
  end

  # Remove credential by friendly name
  def self.remove_credential(config_file : String, name : String) : Bool
    return false unless File.exists?(config_file)

    # First get the UUID
    meta = load_credential_meta(config_file, name)
    return false unless meta

    config = YAML.parse(File.read(config_file))
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    # Remove from db_credentials_meta
    if meta_section = config_hash[YAML::Any.new("db_credentials_meta")]?
      if meta_hash = meta_section.as_h?
        meta_hash = meta_hash.dup
        meta_hash.delete(YAML::Any.new(name))
        config_hash[YAML::Any.new("db_credentials_meta")] = YAML::Any.new(meta_hash)
      end
    end

    # Remove from encrypted_db_credentials
    if creds_section = config_hash[YAML::Any.new("encrypted_db_credentials")]?
      if creds_hash = creds_section.as_h?
        creds_hash = creds_hash.dup
        creds_hash.delete(YAML::Any.new(meta.uuid))
        config_hash[YAML::Any.new("encrypted_db_credentials")] = YAML::Any.new(creds_hash)
      end
    end

    # Write back to file
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o640)
    true
  rescue
    false
  end

  # Load credential secrets (username, password, etc.) by UUID
  def self.load_credential_secrets(config_file : String, uuid : String, signing_key : Ed25519::SigningKey) : JSON::Any?
    encrypted = load_credentials(config_file, uuid, signing_key, silent: true)
    return nil unless encrypted

    JSON.parse(encrypted)
  rescue
    nil
  end
end
