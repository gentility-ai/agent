# MIT License
#
# Copyright (c) 2025 Gentility AI
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require "http/web_socket"
require "json"
require "msgpack"
require "uri"
require "process"
require "file"
require "crotp"
require "qr-code"
require "yaml"
require "ed25519"
require "base58"
require "crypto/subtle"
require "openssl/cipher"
require "base64"

# Read version from VERSION file at compile time
VERSION = {{ read_file("VERSION").strip }}

# Global security state management
module Security
  @@mode : String = "none"
  @@password : String? = nil
  @@totp_secret : String? = nil
  @@unlock_timeout : Int32 = 1800
  @@extendable : Bool = true
  @@active : Bool = false
  @@unlock_time : Time? = nil
  @@initial_unlock_time : Time? = nil
  @@promiscuous_enabled : Bool = true
  @@promiscuous_auth_mode : String = "password"

  def self.configure(mode : String, password : String?, totp_secret : String?, timeout : Int32, extendable : Bool, promiscuous_enabled : Bool = true, promiscuous_auth_mode : String = "password")
    @@mode = mode
    @@password = password
    @@totp_secret = totp_secret
    @@unlock_timeout = timeout
    @@extendable = extendable
    @@promiscuous_enabled = promiscuous_enabled
    @@promiscuous_auth_mode = promiscuous_auth_mode
  end

  def self.mode
    @@mode
  end

  def self.unlocked?
    return true if @@mode == "none"

    return false unless @@active

    now = Time.utc
    return false unless @@unlock_time && @@initial_unlock_time

    # Check if we've exceeded the hard timeout from initial unlock
    if now - @@initial_unlock_time.not_nil! > @@unlock_timeout.seconds
      lock
      return false
    end

    # If extendable, also check the rolling timeout
    if @@extendable && now - @@unlock_time.not_nil! > @@unlock_timeout.seconds
      lock
      return false
    end

    true
  end

  def self.unlock(password_or_totp : String) : Bool
    return true if @@mode == "none"

    success = case @@mode
              when "password"
                @@password && password_or_totp == @@password
              when "totp"
                validate_totp(password_or_totp)
              else
                false
              end

    if success
      now = Time.utc
      @@active = true
      @@unlock_time = now
      @@initial_unlock_time = now unless @@initial_unlock_time
    end

    !!success
  end

  def self.extend_unlock
    return unless @@active && @@extendable
    @@unlock_time = Time.utc
  end

  def self.lock
    @@active = false
    @@unlock_time = nil
    @@initial_unlock_time = nil
  end

  def self.time_remaining : Int32
    return -1 if @@mode == "none" || !@@active
    return 0 unless @@unlock_time && @@initial_unlock_time

    now = Time.utc
    initial_elapsed = (now - @@initial_unlock_time.not_nil!).total_seconds.to_i
    hard_remaining = @@unlock_timeout - initial_elapsed

    if @@extendable
      rolling_elapsed = (now - @@unlock_time.not_nil!).total_seconds.to_i
      rolling_remaining = @@unlock_timeout - rolling_elapsed
      [hard_remaining, rolling_remaining].min
    else
      hard_remaining
    end
  end

  def self.status
    {
      "security_enabled" => @@mode != "none",
      "security_mode"    => @@mode,
      "active"           => unlocked?,
      "time_remaining"   => time_remaining,
      "extendable"       => @@extendable,
    }
  end

  def self.validate_promiscuous_auth(credential : String) : Bool
    return false unless @@promiscuous_enabled

    success = case @@promiscuous_auth_mode
              when "password"
                @@password && credential == @@password
              when "totp"
                validate_totp(credential)
              else
                false
              end

    !!success
  end

  def self.promiscuous_enabled?
    @@promiscuous_enabled
  end

  def self.export_config
    {
      "success"         => true,
      "security_config" => {
        "mode"                  => @@mode,
        "password"              => @@password,
        "totp_secret"           => @@totp_secret,
        "timeout"               => @@unlock_timeout,
        "extendable"            => @@extendable,
        "promiscuous_enabled"   => @@promiscuous_enabled,
        "promiscuous_auth_mode" => @@promiscuous_auth_mode,
      },
    }
  end

  private def self.validate_totp(code : String) : Bool
    return false unless @@totp_secret

    begin
      totp = CrOTP::TOTP.new(@@totp_secret.not_nil!)
      totp.verify(code)
    rescue
      false
    end
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
    File.chmod(config_file, 0o600)
  end

  # Load and decrypt credentials from config file
  def self.load_credentials(config_file : String, db_target_id : String, signing_key : Ed25519::SigningKey) : String?
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
    puts "Warning: Failed to load credentials for #{db_target_id}: #{ex.message}"
    nil
  end
end

class GentilityAgent
  @websocket : HTTP::WebSocket?
  @access_key : String
  @server_url : String
  @nickname : String
  @environment : String
  @running : Bool = false
  @ping_fiber : Fiber?
  @debug : Bool = false
  @signing_key : Ed25519::SigningKey
  @public_key : String

  def initialize(@access_key : String, @server_url : String, @nickname : String, @environment : String = "prod", @debug : Bool = false)
    # Parse Ed25519 private key from access_key
    @signing_key = parse_and_validate_key(@access_key)
    @public_key = AgentCrypto.public_key_base58(@signing_key)

    puts "Agent Public Key: #{@public_key}" if @debug

    load_security_config
  end

  private def parse_and_validate_key(access_key : String) : Ed25519::SigningKey
    AgentCrypto.parse_private_key(access_key)
  rescue ex : Ed25519::VerifyError
    puts "❌ Error: Invalid access key format"
    puts ""
    puts "The provided access key is not a valid Ed25519 private key."
    puts "Ed25519 keys must be exactly 32 bytes when decoded from base58."
    puts ""
    puts "Please check that you copied the full key from the Gentility dashboard."
    exit 1
  rescue ex : Exception
    puts "❌ Error parsing access key: #{ex.message}"
    exit 1
  end

  private def load_security_config
    config_file = get_config_path
    config = load_config_from_file(config_file)
    return Security.configure("none", nil, nil, 1800, true, true, "password") unless config

    # Support both YAML security section and legacy flat keys
    security_config = config["security"]? || config

    mode = security_config["mode"]?.try(&.as_s?) ||
           security_config["SECURITY_MODE"]?.try(&.as_s?) || "none"

    password = security_config["password"]?.try(&.as_s?) ||
               security_config["SECURITY_PASSWORD"]?.try(&.as_s?)

    totp_secret = security_config["totp_secret"]?.try(&.as_s?) ||
                  security_config["SECURITY_TOTP_SECRET"]?.try(&.as_s?)

    timeout = security_config["unlock_timeout"]?.try(&.as_i?) ||
              security_config["SECURITY_UNLOCK_TIMEOUT"]?.try(&.as_i?) || 1800

    extendable = security_config["extendable"]?.try(&.as_bool?) ||
                 security_config["SECURITY_EXTENDABLE"]?.try { |v| parse_boolean_from_any(v) } ||
                 true

    promiscuous_enabled = security_config["promiscuous_enabled"]?.try(&.as_bool?) ||
                          security_config["PROMISCUOUS_ENABLED"]?.try { |v| parse_boolean_from_any(v) } ||
                          true

    promiscuous_auth_mode = security_config["promiscuous_auth_mode"]?.try(&.as_s?) ||
                            security_config["PROMISCUOUS_AUTH_MODE"]?.try(&.as_s?) || "password"

    Security.configure(mode, password, totp_secret, timeout, extendable, promiscuous_enabled, promiscuous_auth_mode)
  end

  private def parse_boolean_from_any(value : YAML::Any) : Bool
    if bool_val = value.as_bool?
      bool_val
    elsif str_val = value.as_s?
      parse_boolean(str_val, false)
    else
      false
    end
  end

  private def parse_boolean(value : String?, default : Bool) : Bool
    return default unless value
    case value.downcase
    when "true", "1", "yes", "on"
      true
    when "false", "0", "no", "off"
      false
    else
      default
    end
  end

  private def save_security_config(mode : String, password : String?, totp_secret : String?, timeout : Int32, extendable : Bool)
    config_file = get_config_path

    # Read and parse existing YAML config
    config = if File.exists?(config_file)
               YAML.parse(File.read(config_file))
             else
               YAML.parse("{}")
             end

    # Convert to hash for modification
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    # Create or update security section
    security_hash = {} of YAML::Any => YAML::Any
    security_hash[YAML::Any.new("mode")] = YAML::Any.new(mode)
    security_hash[YAML::Any.new("password")] = YAML::Any.new(password) if password
    security_hash[YAML::Any.new("totp_secret")] = YAML::Any.new(totp_secret) if totp_secret
    security_hash[YAML::Any.new("unlock_timeout")] = YAML::Any.new(timeout.to_i64)
    security_hash[YAML::Any.new("extendable")] = YAML::Any.new(extendable)

    config_hash[YAML::Any.new("security")] = YAML::Any.new(security_hash)

    # Write updated config
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o600)
  rescue ex : Exception
    puts "Warning: Could not save security configuration to file: #{ex.message}"
  end

  def start
    puts "Starting Gentility Agent v#{VERSION}..."
    puts "Nickname: #{@nickname}"
    puts "Environment: #{@environment}"
    puts "Server: #{@server_url}"
    puts "Debug mode: #{@debug ? "enabled" : "disabled"}"
    puts ""
    puts ""

    @running = true
    retry_count = 0
    max_retries = -1    # Infinite retries
    base_backoff = 1.0  # Start with 1 second
    max_backoff = 300.0 # Cap at 5 minutes
    current_backoff = base_backoff

    while @running
      begin
        connect
        # Reset backoff on successful connection
        retry_count = 0
        current_backoff = base_backoff

        # Keep the main fiber alive while connected
        while @running && @websocket && !@websocket.not_nil!.closed?
          sleep 1.second
        end

        # If we get here, the connection was closed
        if @running
          puts "Connection lost, will attempt to reconnect..."
        end
      rescue ex : Exception
        if @running
          retry_count += 1
          puts "Connection error (attempt #{retry_count}): #{ex.message}"

          if max_retries > 0 && retry_count >= max_retries
            puts "Maximum retry attempts (#{max_retries}) reached. Exiting..."
            exit 1
          else
            # Exponential backoff with jitter
            jitter = Random.rand * 0.3 * current_backoff # Add 0-30% jitter
            wait_time = current_backoff + jitter

            puts "Waiting #{wait_time.round(1)} seconds before reconnection attempt (exponential backoff)..."
            sleep wait_time.seconds

            # Double the backoff for next time, but cap at max_backoff
            current_backoff = [current_backoff * 2.0, max_backoff].min

            puts "Attempting to reconnect..."
          end
        end
      end
    end

    puts "Agent stopped."
  end

  def stop
    puts "Stopping agent..."
    @running = false

    # The ping fiber will stop naturally when @running becomes false

    # Close WebSocket
    @websocket.try(&.close)
  end

  private def debug_log(message : String)
    if @debug
      puts "[DEBUG] #{Time.local.to_s("%Y-%m-%d %H:%M:%S")} #{message}"
    end
  end

  private def connect
    # Clean up any existing connection
    @websocket.try(&.close) if @websocket
    @websocket = nil
    @ping_fiber = nil

    # Parse server URL and create WebSocket URL
    uri = URI.parse(@server_url)
    ws_uri = URI.new(
      scheme: (uri.scheme == "https" || uri.scheme == "wss") ? "wss" : "ws",
      host: uri.host,
      port: uri.port,
      path: "/agent/ws/websocket",
      query: URI::Params.build do |params|
        params.add "access_key", @public_key # Send public key for authentication
        params.add "version", VERSION
        params.add "security_mode", Security.mode
        params.add "security_enabled", (Security.mode != "none").to_s
        params.add "security_active", Security.unlocked?.to_s
      end
    )

    puts "Connecting to #{ws_uri}..."

    # Connect to WebSocket
    @websocket = HTTP::WebSocket.new(ws_uri)

    # Set up message handlers
    @websocket.not_nil!.on_message do |message|
      handle_message(message)
    end

    @websocket.not_nil!.on_binary do |binary|
      handle_binary_message(binary)
    end

    @websocket.not_nil!.on_close do |close_code, message|
      puts "WebSocket closed: #{close_code} - #{message}"
      @websocket = nil
    end

    # Note: HTTP::WebSocket doesn't have on_error callback
    # Errors will be handled in the rescue blocks

    # Start the WebSocket in a non-blocking way
    spawn do
      @websocket.not_nil!.run
    end

    # Wait a bit for connection to establish
    sleep 1.second

    if @websocket && !@websocket.not_nil!.closed?
      puts "Connected successfully!"

      # Start ping mechanism
      start_ping_loop

      # Send initial status
      send_status
    else
      raise "Failed to establish WebSocket connection"
    end
  end

  private def handle_message(message : String)
    # For debugging - shouldn't receive text messages normally
    puts "Received text message: #{message}"
  end

  private def handle_binary_message(binary : Bytes)
    debug_log("← Received binary message (#{binary.size} bytes)")

    begin
      # Unpack MessagePack
      data = MessagePack.unpack(binary)
      debug_log("← Unpacked: #{data.inspect}")

      # Work directly with the MessagePack::Any data
      handle_parsed_message(data)
    rescue ex : Exception
      puts "Error parsing binary message: #{ex.message}"
      debug_log("← Parse error: #{ex.message}")
    end
  end

  private def handle_parsed_message(msg : MessagePack::Any)
    case msg["type"]?.try(&.to_s)
    when "welcome"
      puts "Received welcome from server!"
      server_target_id = msg["server_target_id"]?.try(&.to_s)
      puts "Server Target ID: #{server_target_id}" if server_target_id
    when "ping"
      # Respond to ping with security status
      response = {"type" => "pong", "timestamp" => Time.utc.to_unix_f}
      response = response.merge(Security.status)
      send_message(response)
    when "pong"
      # Handle pong response (server responding to our ping)
      timestamp = msg["timestamp"]?.try(&.as_f?)
      if timestamp
        # Calculate round-trip time if we want
        current_time = Time.utc.to_unix_f
        rtt = current_time - timestamp
        puts "Received pong from server (RTT: #{(rtt * 1000).round(2)}ms)" if rtt > 0
      else
        puts "Received pong from server"
      end
    when "command"
      handle_command(msg)
    else
      puts "Unknown message type: #{msg["type"]?}"
      puts "Full message: #{msg}"
    end
  end

  private def handle_command(msg : MessagePack::Any)
    request_id = msg["request_id"]?.try(&.to_s)
    command = msg["command"]?.try(&.to_s)
    params = msg["params"]?

    puts "Received command: #{command} (#{request_id})"

    unless request_id && command
      puts "Invalid command message - missing request_id or command"
      return
    end

    # Execute command in background
    spawn do
      begin
        result = execute_command(command, params)
        send_response(request_id, result)
      rescue ex : Exception
        send_error(request_id, ex.message || "Unknown error")
      end
    end
  end

  private def execute_command(command : String, params : MessagePack::Any?)
    case command
    when "ping"
      {"status" => "pong", "timestamp" => Time.utc.to_unix_f}
    when "system_info"
      get_system_info
    when "check_capabilities"
      if capabilities = params.try(&.["capabilities"]?.try(&.as_a?))
        check_capabilities(capabilities)
      else
        {"error" => "Missing capabilities parameter"}
      end
    when "execute"
      return {"error" => "Agent unlock required for command execution"} unless Security.unlocked?
      Security.extend_unlock
      cmd = params.try(&.["command"]?.try(&.to_s))
      if cmd
        execute_shell_command(cmd)
      else
        {"error" => "Missing command parameter"}
      end
    when "file_read"
      path = params.try(&.["path"]?.try(&.to_s))
      if path
        read_file(path)
      else
        {"error" => "Missing path parameter"}
      end
    when "file_write"
      path = params.try(&.["path"]?.try(&.to_s))
      content = params.try(&.["content"]?.try(&.to_s))
      if path && content
        write_file(path, content)
      else
        {"error" => "Missing path or content parameter"}
      end
    when "psql_query"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      Security.extend_unlock
      host = params.try(&.["host"]?.try(&.to_s))
      port = params.try(&.["port"]?.try(&.as_i?))
      dbname = params.try(&.["dbname"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))
      username = params.try(&.["user"]?.try(&.to_s)) || params.try(&.["username"]?.try(&.to_s))
      password = params.try(&.["password"]?.try(&.to_s))

      if host && port && dbname && query
        execute_psql_query(host, port, dbname, query, username, password)
      else
        {"error" => "Missing required parameters: host, port, dbname, query"}
      end
    when "mysql_query"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      Security.extend_unlock
      host = params.try(&.["host"]?.try(&.to_s))
      port = params.try(&.["port"]?.try(&.as_i?))
      dbname = params.try(&.["dbname"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if host && port && dbname && query
        execute_mysql_query(host, port, dbname, query)
      else
        {"error" => "Missing required parameters: host, port, dbname, query"}
      end
    when "psql_query_encrypted"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      Security.extend_unlock

      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if db_target_id && query
        # Load credentials from encrypted storage
        config_file = get_config_path
        creds_json = AgentCrypto.load_credentials(config_file, db_target_id, @signing_key)

        unless creds_json
          return {"error" => "Credentials not found for db_target_id: #{db_target_id}"}
        end

        # Parse credentials JSON
        creds = JSON.parse(creds_json)
        host = creds["host"]?.try(&.as_s)
        port = creds["port"]?.try(&.as_i)
        dbname = creds["database"]?.try(&.as_s)
        username = creds["username"]?.try(&.as_s)
        password = creds["password"]?.try(&.as_s)

        if host && port && dbname
          execute_psql_query(host, port, dbname, query, username, password)
        else
          {"error" => "Invalid stored credentials"}
        end
      else
        {"error" => "Missing required parameters: db_target_id, query"}
      end
    when "mysql_query_encrypted"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      Security.extend_unlock

      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if db_target_id && query
        # Load credentials from encrypted storage
        config_file = get_config_path
        creds_json = AgentCrypto.load_credentials(config_file, db_target_id, @signing_key)

        unless creds_json
          return {"error" => "Credentials not found for db_target_id: #{db_target_id}"}
        end

        # Parse credentials JSON
        creds = JSON.parse(creds_json)
        host = creds["host"]?.try(&.as_s)
        port = creds["port"]?.try(&.as_i)
        dbname = creds["database"]?.try(&.as_s)

        if host && port && dbname
          execute_mysql_query(host, port, dbname, query)
        else
          {"error" => "Invalid stored credentials"}
        end
      else
        {"error" => "Missing required parameters: db_target_id, query"}
      end
    when "security_unlock"
      credential = params.try(&.["credential"]?.try(&.to_s))
      if credential
        if Security.unlock(credential)
          send_status # Send updated security status
          {"success" => true, "message" => "Agent unlocked successfully"}
        else
          {"error" => "Invalid credentials"}
        end
      else
        {"error" => "Missing credential parameter"}
      end
    when "security_lock"
      Security.lock
      send_status # Send updated security status
      {"success" => true, "message" => "Agent locked"}
    when "security_export"
      credential = params.try(&.["credential"]?.try(&.to_s))
      if credential && Security.validate_promiscuous_auth(credential)
        Security.export_config
      else
        {"error" => Security.promiscuous_enabled? ? "Invalid promiscuous credentials" : "Promiscuous mode disabled"}
      end
    when "security_set"
      # Only allow configuration if no security is currently set, or if already unlocked
      if Security.mode == "none" || Security.unlocked?
        mode = params.try(&.["mode"]?.try(&.to_s))
        password = params.try(&.["password"]?.try(&.to_s))
        totp_secret = params.try(&.["totp_secret"]?.try(&.to_s))
        timeout = params.try(&.["timeout"]?.try(&.as_i?)) || 1800
        extendable = params.try(&.["extendable"]?.try(&.as_bool?)) || true

        if mode && (mode == "none" || password || totp_secret)
          Security.configure(mode, password, totp_secret, timeout, extendable)
          save_security_config(mode, password, totp_secret, timeout, extendable)
          send_status # Send updated security status
          {"success" => true, "message" => "Security configuration updated"}
        else
          {"error" => "Invalid security configuration parameters"}
        end
      else
        {"error" => "Agent unlock required to change security settings"}
      end
    when "security_unset"
      # Only allow unsetting if no security is currently set, or if already unlocked
      if Security.mode == "none" || Security.unlocked?
        Security.configure("none", nil, nil, 1800, true)
        save_security_config("none", nil, nil, 1800, true)
        send_status # Send updated security status
        {"success" => true, "message" => "Security disabled"}
      else
        {"error" => "Agent unlock required to change security settings"}
      end
    when "get_status"
      # Send current status and return success
      send_status
      {"success" => true, "message" => "Status update sent"}
    when "store_credentials"
      # Store encrypted database credentials on the agent
      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      credentials = params.try(&.["credentials"]?.try(&.to_s))

      if db_target_id && credentials
        begin
          config_file = get_config_path
          AgentCrypto.store_credentials(config_file, db_target_id, credentials, @signing_key)
          {"success" => true, "message" => "Credentials stored securely"}
        rescue ex : Exception
          {"error" => "Failed to store credentials: #{ex.message}"}
        end
      else
        {"error" => "Missing db_target_id or credentials parameter"}
      end
    else
      {"error" => "Unknown command: #{command}"}
    end
  end

  private def get_system_info
    {
      "hostname"     => `hostname`.strip,
      "os"           => `uname -s`.strip,
      "architecture" => `uname -m`.strip,
      "uptime"       => `uptime`.strip,
      "load_avg"     => `cat /proc/loadavg 2>/dev/null || uptime | grep -o 'load average.*'`.strip,
      "disk_usage"   => `df -h / | tail -1`.strip,
      "memory"       => `free -h 2>/dev/null || vm_stat | head -10`.strip,
    }
  rescue ex : Exception
    {"error" => "Failed to get system info: #{ex.message}"}
  end

  private def check_capabilities(capabilities_list : Array(MessagePack::Type))
    available_packages = [] of String

    capabilities_list.each do |capability|
      if capability_name = capability.try(&.to_s)
        if command_available?(capability_name)
          available_packages << capability_name
        end
      end
    end

    {
      "available_capabilities" => available_packages, # Keep old name for backward compatibility
      "available_packages"     => available_packages, # New name
      "total_checked"          => capabilities_list.size,
      "total_available"        => available_packages.size,
      "timestamp"              => Time.utc.to_unix_f,
    }
  rescue ex : Exception
    {"error" => "Failed to check packages: #{ex.message}"}
  end

  private def command_available?(command : String) : Bool
    # Use 'which' to check if command is available
    result = `which #{command} 2>/dev/null`.strip
    !result.empty?
  rescue
    false
  end

  private def get_available_tools
    [
      "ping",
      "system_info",
      "check_capabilities",
      "execute",
      "file_read",
      "file_write",
      "psql_query",
      "mysql_query",
      "security_unlock",
      "security_lock",
      "security_export",
      "security_set",
      "security_unset",
      "get_status",
    ]
  end

  private def execute_shell_command(cmd : String)
    puts "Executing: #{cmd}"

    begin
      process = Process.new(
        cmd,
        shell: true,
        input: Process::Redirect::Close,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Pipe
      )

      stdout = process.output.gets_to_end
      stderr = process.error.gets_to_end
      exit_status = process.wait

      {
        "stdout"    => stdout,
        "stderr"    => stderr,
        "exit_code" => exit_status.exit_code,
        "success"   => exit_status.success?,
      }
    rescue ex : Exception
      {
        "stdout"    => "",
        "stderr"    => ex.message || "Unknown error",
        "exit_code" => -1,
        "success"   => false,
        "error"     => "Failed to execute command: #{ex.message}",
      }
    end
  end

  private def read_file(path : String)
    if File.exists?(path)
      content = File.read(path)
      {
        "content" => content,
        "size"    => content.bytesize,
        "exists"  => true,
      }
    else
      {"error" => "File not found: #{path}", "exists" => false}
    end
  rescue ex : Exception
    {"error" => "Failed to read file: #{ex.message}"}
  end

  private def write_file(path : String, content : String)
    File.write(path, content)
    {
      "success"       => true,
      "bytes_written" => content.bytesize,
    }
  rescue ex : Exception
    {"error" => "Failed to write file: #{ex.message}"}
  end

  private def execute_psql_query(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?)
    puts "Executing PostgreSQL query on #{host}:#{port}/#{dbname}"
    puts "Query: #{query}"

    begin
      # Use psql with environment variable to avoid password prompt
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")

      # Build the psql command with proper authentication
      psql_cmd = "PGPASSWORD='#{password || ""}' psql -h #{host} -p #{port}"
      psql_cmd += " -U #{username}" if username
      psql_cmd += " -d #{dbname} -t -A -c \"#{escaped_query}\""

      execute_db_command(psql_cmd, "|", "PostgreSQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute PostgreSQL query: #{ex.message}",
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  private def execute_mysql_query(host : String, port : Int32, dbname : String, query : String)
    puts "Executing MySQL query on #{host}:#{port}/#{dbname}"
    puts "Query: #{query}"

    begin
      # Use mysql with batch mode to avoid password prompt
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")
      mysql_cmd = "mysql -h #{host} -P #{port} -D #{dbname} --batch --raw --skip-column-names -e \"#{escaped_query}\""

      execute_db_command(mysql_cmd, "\t", "MySQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute MySQL query: #{ex.message}",
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  private def execute_db_command(command : String, delimiter : String, db_type : String)
    puts "Executing: #{command}"

    process = Process.new(
      command,
      shell: true,
      input: Process::Redirect::Close,
      output: Process::Redirect::Pipe,
      error: Process::Redirect::Pipe
    )

    stdout = process.output.gets_to_end
    stderr = process.error.gets_to_end
    exit_status = process.wait

    if exit_status.success?
      # Parse the output into rows
      rows = if stdout.strip.empty?
               [] of Array(String)
             else
               stdout.strip.split("\n").map do |line|
                 line.split(delimiter).map(&.strip)
               end
             end

      {
        "success"   => true,
        "rows"      => rows,
        "row_count" => rows.size,
      }
    else
      error_message = stderr.empty? ? "Query failed" : stderr.strip

      # Provide helpful authentication error messages
      if error_message.includes?("authentication") || error_message.includes?("Access denied")
        error_message = "#{db_type} authentication required. Please configure credentials on the agent server."
      end

      {
        "success"   => false,
        "error"     => error_message,
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  private def send_response(request_id : String, result)
    send_message({
      "type"       => "response",
      "request_id" => request_id,
      "result"     => result,
    })
  end

  private def send_error(request_id : String, error : String)
    send_message({
      "type"       => "error",
      "request_id" => request_id,
      "error"      => error,
    })
  end

  private def send_status
    status = {
      "agent_version" => VERSION,
      "hostname"      => get_hostname,
      "local_ip"      => get_local_ip,
      "environment"   => @environment,
      "nickname"      => @nickname,
      "uptime"        => Time.monotonic.total_seconds,
      "timestamp"     => Time.utc.to_unix_f,
      "tools"         => get_available_tools,
    }

    # Merge security status
    status = status.merge(Security.status)

    send_message({
      "type"   => "status",
      "status" => status,
    })
  rescue ex : Exception
    puts "Error sending status: #{ex.message}"
  end

  private def get_hostname : String
    `hostname`.strip
  rescue
    "unknown"
  end

  private def get_local_ip : String
    # Try to get the local IP address (not 127.0.0.1)
    # First try to get IP from common network interfaces
    interfaces = ["eth0", "ens3", "ens33", "en0", "wlan0"]

    interfaces.each do |interface|
      # Try Linux-style ip command first
      result = `ip addr show #{interface} 2>/dev/null | grep -o 'inet [0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*' | grep -o '[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*'`.strip
      if !result.empty? && result != "127.0.0.1"
        return result
      end

      # Try macOS/BSD-style ifconfig
      result = `ifconfig #{interface} 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}'`.strip
      if !result.empty? && result != "127.0.0.1"
        return result
      end
    end

    # Fallback: try to get IP by connecting to a remote address (doesn't actually connect)
    result = `ip route get 8.8.8.8 2>/dev/null | grep -o 'src [0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*' | grep -o '[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*'`.strip
    if !result.empty?
      return result
    end

    # Try macOS route command
    result = `route get default 2>/dev/null | grep interface | awk '{print $2}'`.strip
    if !result.empty?
      result = `ifconfig #{result} 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}'`.strip
      if !result.empty?
        return result
      end
    end

    # Last resort: try hostname -I
    result = `hostname -I 2>/dev/null`.strip
    if !result.empty?
      # Take the first IP that's not 127.0.0.1
      ips = result.split(" ")
      ips.each do |ip|
        if ip != "127.0.0.1" && !ip.starts_with?("127.")
          return ip
        end
      end
    end

    # If all else fails, return localhost
    "127.0.0.1"
  rescue
    "unknown"
  end

  private def start_ping_loop
    @ping_fiber = spawn do
      loop do
        break unless @running && @websocket && !@websocket.not_nil!.closed?

        # Send ping every 30 seconds
        sleep 30.seconds

        if @websocket && !@websocket.not_nil!.closed?
          send_message({"type" => "ping", "timestamp" => Time.utc.to_unix_f})
        end
      end
    end
  end

  # Helper method to send a message with automatic type conversion
  private def send_message(data : Hash)
    debug_log("→ Sending: #{data.inspect}")

    # Pack and send the data directly
    websocket = @websocket
    return unless websocket && !websocket.closed?

    begin
      packed = data.to_msgpack
      debug_log("→ Packed message (#{packed.size} bytes)")
      websocket.send(packed)
    rescue ex : Exception
      puts "Error sending message: #{ex.message}"
      debug_log("→ Send error: #{ex.message}")
    end
  end
end

# Configuration and argument parsing
def load_config_from_file(path : String) : YAML::Any?
  return nil unless File.exists?(path)

  YAML.parse(File.read(path))
rescue ex : Exception
  puts "Error reading config file: #{ex.message}"
  nil
end

def parse_arguments
  # 1. Start with defaults
  access_key = nil
  server_url = "wss://core.gentility.ai"
  nickname = `hostname`.strip
  environment = "prod"
  debug = false

  # 2. Load configuration from file if it exists
  config_file = get_config_path
  config = load_config_from_file(config_file)

  # Apply config file settings (YAML format)
  if config
    # Support both snake_case (YAML convention) and legacy SCREAMING_CASE
    access_key = config["access_key"]?.try(&.as_s?) ||
                 config["ACCESS_KEY"]?.try(&.as_s?) ||
                 config["GENTILITY_TOKEN"]?.try(&.as_s?)

    server_url = config["server_url"]?.try(&.as_s?) ||
                 config["SERVER_URL"]?.try(&.as_s?) ||
                 server_url

    nickname = config["nickname"]?.try(&.as_s?) ||
               config["NICKNAME"]?.try(&.as_s?) ||
               nickname

    environment = config["environment"]?.try(&.as_s?) ||
                  config["ENVIRONMENT"]?.try(&.as_s?) ||
                  environment

    debug = config["debug"]?.try(&.as_bool?) ||
            config["DEBUG"]?.try { |v| v.as_s?.try { |s| s.downcase == "true" || s == "1" || s.downcase == "yes" } } ||
            debug
  end

  # 3. Override with environment variables (systemd loads config as env vars too)
  if ENV["GENTILITY_TOKEN"]?
    access_key = ENV["GENTILITY_TOKEN"]
  end

  if ENV["SERVER_URL"]?
    server_url = ENV["SERVER_URL"]
  end

  if ENV["NICKNAME"]?
    nickname = ENV["NICKNAME"]
  end

  if ENV["ENVIRONMENT"]?
    environment = ENV["ENVIRONMENT"]
  end

  if ENV["DEBUG"]?
    debug_env = ENV["DEBUG"].downcase
    debug = (debug_env == "true" || debug_env == "1" || debug_env == "yes")
  end

  # 4. Override with CLI arguments (highest priority)
  # Check for --token and --debug arguments
  ARGV.each_with_index do |arg, index|
    if arg.starts_with?("--token=")
      access_key = arg.split("=", 2)[1]
    elsif arg == "--debug"
      debug = true
    end
  end

  # Check for legacy positional arguments (backward compatibility)
  non_token_args = ARGV.reject { |arg| arg.starts_with?("--token=") || arg == "--debug" }

  if non_token_args.size > 0 && !ARGV.any? { |arg| arg.starts_with?("--token=") }
    access_key = non_token_args[0]
  end

  if non_token_args.size > 1
    server_url = non_token_args[1]
  end

  if non_token_args.size > 2
    nickname = non_token_args[2]
  end

  if non_token_args.size > 3
    environment = non_token_args[3]
  end

  unless access_key
    puts "ERROR: No access token provided!"
    puts ""
    puts "To start the agent, use the run command with a token:"
    puts "  gentility run --token=YOUR_TOKEN_HERE"
    puts ""
    puts "Or configure it permanently first:"
    puts "  sudo gentility setup YOUR_TOKEN_HERE"
    puts "  gentility run"
    puts ""
    puts "For help: gentility help"
    exit 1
  end

  {access_key, server_url, nickname, environment, debug}
end

def get_config_path : String
  # Check for environment variable first (used by Homebrew service)
  if config_path = ENV["GENTILITY_CONFIG"]?
    return config_path
  end

  # Platform-specific defaults
  {% if flag?(:darwin) %}
    # macOS - check for Homebrew installation
    if File.exists?("/opt/homebrew/etc")
      return "/opt/homebrew/etc/gentility.yaml"
    elsif File.exists?("/usr/local/etc")
      return "/usr/local/etc/gentility.yaml"
    end
  {% end %}

  # Default to /etc for Linux and other systems
  "/etc/gentility.yaml"
end

def setup_config(token : String)
  config_file = get_config_path

  # Check if config file already exists
  if File.exists?(config_file)
    puts "📝 Configuration file #{config_file} already exists."
    puts "Updating access_key..."

    # Read and parse existing YAML config
    config = YAML.parse(File.read(config_file))
    config_hash = config.as_h? || {} of YAML::Any => YAML::Any
    config_hash[YAML::Any.new("access_key")] = YAML::Any.new(token)

    # Write updated config back
    File.write(config_file, config_hash.to_yaml)
    puts "✅ Token updated in #{config_file}"
    puts ""
    puts "You can now start the service with:"
    puts "  gentility run"
    puts "  # Or as a service:"
    puts "  brew services start gentility-agent  # macOS"
    puts "  sudo systemctl start gentility        # Linux"
    exit 0
  end

  # Check if we have permissions to write to /etc
  begin
    # Create full config content in YAML format
    config_content = <<-CONFIG
    # Gentility AI Agent Configuration
    # Automatically generated by gentility setup

    # REQUIRED: Your Gentility AI access token (Ed25519 private key in base58)
    access_key: "#{token}"

    # OPTIONAL: Server URL (default: wss://core.gentility.ai)
    # server_url: wss://core.gentility.ai

    # OPTIONAL: Agent nickname (default: hostname)
    # nickname: #{`hostname`.strip}

    # OPTIONAL: Environment (default: prod)
    # environment: prod

    # OPTIONAL: Debug logging (default: false)
    # debug: false

    # Security configuration
    security:
      # Security mode: none, password, or totp (default: none)
      # mode: none

      # Password for password mode
      # password: your_secure_password

      # TOTP secret for totp mode (base32 encoded)
      # totp_secret: JBSWY3DPEHPK3PXP

      # Unlock timeout in seconds (default: 1800 = 30 minutes)
      # unlock_timeout: 1800

      # Allow extending timeout on activity (default: true)
      # extendable: true

      # Promiscuous mode - allow server to export security config (default: true)
      # promiscuous_enabled: true

      # Promiscuous authentication mode: password or totp (default: password)
      # promiscuous_auth_mode: password

    # Encrypted database credentials (managed by server)
    encrypted_db_credentials:
      # Database credentials will be stored here as:
      # db-target-uuid: base64_encrypted_credentials
    CONFIG

    # Write the config file
    File.write(config_file, config_content)

    # Set proper permissions (readable only by root)
    File.chmod(config_file, 0o600)

    puts "✅ Configuration saved to #{config_file}"
    puts ""
    puts "You can now start the service with:"
    puts "  sudo systemctl start gentility"
    puts "  sudo systemctl enable gentility"
    puts ""
    puts "To check the status:"
    puts "  sudo systemctl status gentility"

    exit 0
  rescue ex : File::AccessDeniedError
    puts "❌ Error: Permission denied. Please run with sudo:"
    puts "  sudo #{PROGRAM_NAME} setup YOUR_TOKEN"
    exit 1
  rescue ex
    puts "❌ Error saving configuration: #{ex.message}"
    exit 1
  end
end

def generate_totp_secret(length : Int32 = 32) : String
  # Generate a random base32 secret
  chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  secret = ""
  length.times do
    secret += chars[Random.rand(chars.size)]
  end
  secret
end

def generate_qr_ascii(text : String) : String
  begin
    # Use pure Crystal QR code library - no external dependencies!
    # Try different sizes until one works for the URL length
    qr = nil
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].each do |size|
      begin
        qr = QRCode.new(text, size: size, level: :l) # Use low error correction for more data
        break
      rescue
        next
      end
    end

    unless qr
      return "QR Code too complex for display.\nManual entry URL: #{text}"
    end

    output = String.build do |str|
      qr.modules.each do |row|
        row.each do |col|
          # Use ANSI background colors for better visibility
          if col
            str << "\033[40m  " # Black background (QR module)
          else
            str << "\033[47m  " # White background (empty space)
          end
        end
        str << "\033[0m\n" # Reset color and newline
      end
    end
    output
  rescue ex : Exception
    # Fallback if QR generation fails
    "QR Code generation failed: #{ex.message}\nManual entry URL: #{text}"
  end
end

def setup_security(mode : String, value : String? = nil)
  config_file = get_config_path

  case mode
  when "totp"
    # Generate TOTP secret if not provided
    secret = value || generate_totp_secret

    puts "🔐 TOTP Security Setup"
    puts "===================="
    puts ""
    puts "Your TOTP secret: #{secret}"
    puts ""
    puts "Add this to your authenticator app by scanning the QR code below"
    puts "or manually entering the secret."
    puts ""

    # Generate QR code URL for authenticator apps (keep it short)
    hostname = `hostname`.strip rescue "agent"
    hostname = hostname[0...10] if hostname.size > 10 # Truncate long hostnames
    issuer = "Gentility"
    totp_url = "otpauth://totp/#{issuer}:#{hostname}?secret=#{secret}&issuer=#{issuer}"

    puts "Authenticator URL:"
    puts totp_url
    puts ""

    # Generate ASCII QR code
    puts "QR Code:"
    puts generate_qr_ascii(totp_url)
    puts ""

    # Update config file
    update_config(config_file, "SECURITY_MODE", "totp")
    update_config(config_file, "SECURITY_TOTP_SECRET", secret)
  when "password"
    password = value
    unless password
      print "Enter password: "
      password = gets.try(&.strip)
    end

    unless password && !password.empty?
      puts "❌ Error: Password cannot be empty"
      exit 1
    end

    puts "🔐 Password Security Setup"
    puts "========================"
    puts "Security mode set to password authentication."
    puts ""

    # Update config file
    update_config(config_file, "SECURITY_MODE", "password")
    update_config(config_file, "SECURITY_PASSWORD", password)
  when "none"
    puts "🔐 Security Disabled"
    puts "==================="
    puts "Security mode set to none - no authentication required."
    puts ""

    update_config(config_file, "SECURITY_MODE", "none")
    remove_config(config_file, ["SECURITY_PASSWORD", "SECURITY_TOTP_SECRET"])
  else
    puts "❌ Error: Invalid security mode. Use: totp, password, or none"
    exit 1
  end

  puts "✅ Security configuration saved to #{config_file}"
  puts ""
  puts "Restart the agent to apply new security settings:"
  puts "  sudo systemctl restart gentility"

  exit 0
rescue ex : Exception
  puts "❌ Error: #{ex.message}"
  exit 1
end

def update_config(config_file : String, key : String, value : String)
  lines = [] of String
  found = false

  if File.exists?(config_file)
    File.each_line(config_file) do |line|
      if line.starts_with?("#{key}=") || line.starts_with?("##{key}=")
        lines << "#{key}=#{value}"
        found = true
      else
        lines << line
      end
    end
  end

  unless found
    lines << "#{key}=#{value}"
  end

  File.write(config_file, lines.join("\n") + "\n")
  File.chmod(config_file, 0o600)
end

def remove_config(config_file : String, keys : Array(String))
  return unless File.exists?(config_file)

  lines = [] of String
  File.each_line(config_file) do |line|
    # Skip lines for the specified keys
    next if keys.any? { |key| line.starts_with?("#{key}=") || line.starts_with?("##{key}=") }
    lines << line
  end

  File.write(config_file, lines.join("\n") + "\n")
  File.chmod(config_file, 0o600)
end

def test_totp_validation(code : String)
  config_file = get_config_path
  config = load_config_from_file(config_file) || {} of String => String

  totp_secret = config["SECURITY_TOTP_SECRET"]?
  mode = config["SECURITY_MODE"]?

  unless mode == "totp"
    puts "❌ Error: TOTP mode is not configured"
    puts "Run: #{PROGRAM_NAME} security totp"
    exit 1
  end

  unless totp_secret
    puts "❌ Error: No TOTP secret found in configuration"
    exit 1
  end

  begin
    totp = CrOTP::TOTP.new(totp_secret.as(String))
    if totp.verify(code)
      puts "✅ TOTP validation successful!"
      puts "Code '#{code}' is valid for the configured secret."
    else
      puts "❌ TOTP validation failed!"
      puts "Code '#{code}' is not valid. Check your authenticator app."
    end
  rescue ex : Exception
    puts "❌ Error validating TOTP: #{ex.message}"
    exit 1
  end

  exit 0
end

def show_promiscuous_status
  config_file = get_config_path
  config = load_config_from_file(config_file) || {} of String => String

  enabled = config["PROMISCUOUS_ENABLED"]? != "false"
  auth_mode = config["PROMISCUOUS_AUTH_MODE"]? || "password"

  puts "🔐 Promiscuous Mode Status"
  puts "========================="
  puts "Enabled: #{enabled ? "✅ Yes" : "❌ No"}"
  puts "Auth Mode: #{auth_mode}"
  puts ""
  puts "Promiscuous mode allows the server to export security"
  puts "configuration for replication to other agents."

  exit 0
end

def set_promiscuous_mode(enabled : Bool)
  config_file = get_config_path

  update_config(config_file, "PROMISCUOUS_ENABLED", enabled.to_s)

  puts "🔐 Promiscuous Mode #{enabled ? "Enabled" : "Disabled"}"
  puts "==============================#{enabled ? "=" : "=========="}"
  puts "Promiscuous mode is now #{enabled ? "enabled" : "disabled"}."
  puts ""
  puts "Restart the agent to apply changes:"
  puts "  sudo systemctl restart gentility"

  exit 0
rescue ex : Exception
  puts "❌ Error: #{ex.message}"
  exit 1
end

def set_promiscuous_auth_mode(mode : String)
  unless ["password", "totp"].includes?(mode)
    puts "❌ Error: Invalid auth mode. Use: password, totp"
    exit 1
  end

  config_file = get_config_path

  update_config(config_file, "PROMISCUOUS_AUTH_MODE", mode)

  puts "🔐 Promiscuous Auth Mode Set"
  puts "==========================="
  puts "Promiscuous authentication mode set to: #{mode}"
  puts ""
  puts "This determines which credential is required for"
  puts "promiscuous operations (uses the same password/TOTP as normal security)."
  puts ""
  puts "Restart the agent to apply changes:"
  puts "  sudo systemctl restart gentility"

  exit 0
rescue ex : Exception
  puts "❌ Error: #{ex.message}"
  exit 1
end

def show_status
  puts "Gentility Agent v#{VERSION}"
  puts "==================#{("=" * VERSION.size)}"
  puts ""

  config_file = get_config_path
  config = load_config_from_file(config_file) || {} of String => String

  # Check if configured
  if config["GENTILITY_TOKEN"]?
    puts "✅ Configuration: Found"
    puts "   Config file: #{config_file}"
  else
    puts "❌ Configuration: Not found"
    puts "   Expected: #{config_file}"
    puts "   Run: sudo gentility setup YOUR_TOKEN"
    puts ""
    return
  end

  # Show basic config
  if token = config["GENTILITY_TOKEN"]?
    puts "   Token: #{token[0..12]}..."
  end
  puts "   Server: #{config["SERVER_URL"]? || "ws://localhost:9000"}"
  puts "   Nickname: #{config["NICKNAME"]? || `hostname`.strip}"
  puts ""

  # Security status
  mode = config["SECURITY_MODE"]? || "none"
  puts "🔐 Security Mode: #{mode}"

  case mode
  when "totp"
    if config["SECURITY_TOTP_SECRET"]?
      puts "   TOTP Secret: Configured"
    else
      puts "   TOTP Secret: Missing"
    end
  when "password"
    if config["SECURITY_PASSWORD"]?
      puts "   Password: Configured"
    else
      puts "   Password: Missing"
    end
  when "none"
    puts "   No authentication required"
  end
  puts ""

  # Service status
  puts "🔄 Service Status:"
  begin
    result = `systemctl is-active gentility 2>/dev/null`.strip
    case result
    when "active"
      puts "   ✅ Running"
    when "inactive"
      puts "   ❌ Stopped"
    when "failed"
      puts "   ❌ Failed"
    else
      puts "   ❓ Unknown (#{result})"
    end

    enabled = `systemctl is-enabled gentility 2>/dev/null`.strip
    puts "   Auto-start: #{enabled == "enabled" ? "✅ Enabled" : "❌ Disabled"}"
  rescue
    puts "   ❓ Unable to check service status"
  end
  puts ""

  # Promiscuous mode
  promiscuous_enabled = config["PROMISCUOUS_ENABLED"]? != "false"
  promiscuous_auth_mode = config["PROMISCUOUS_AUTH_MODE"]? || "password"
  puts "🔗 Promiscuous Mode: #{promiscuous_enabled ? "✅ Enabled" : "❌ Disabled"}"
  if promiscuous_enabled
    puts "   Auth Mode: #{promiscuous_auth_mode}"
  end
  puts ""

  puts "Commands:"
  puts "   gentility run           Start agent"
  puts "   sudo systemctl start gentility    Start service"
  puts "   gentility help          Show help"
end

def show_version
  puts "Gentility AI Agent v#{VERSION}"
end

def generate_keypair
  # Generate a new Ed25519 keypair
  signing_key = Ed25519::SigningKey.new
  private_key_base58 = Base58.encode(signing_key.key_bytes)
  public_key_base58 = AgentCrypto.public_key_base58(signing_key)

  puts "🔑 Generated Ed25519 Keypair"
  puts "============================"
  puts ""
  puts "Private Key (base58):"
  puts private_key_base58
  puts ""
  puts "Public Key (base58):"
  puts public_key_base58
  puts ""
  puts "⚠️  Keep the private key secret and secure!"
  puts "Use the private key as your access token when setting up the agent."
  puts ""
  puts "Next steps:"
  puts "  gentility setup #{private_key_base58}"
  puts ""
end

def show_help
  puts "Gentility AI Agent v#{VERSION}"
  puts "==================#{("=" * VERSION.size)}"
  puts ""
  puts "USAGE:"
  puts "    gentility <COMMAND> [OPTIONS]"
  puts ""
  puts "COMMANDS:"
  puts "    run, start           Start the agent daemon"
  puts "    status               Show agent configuration and service status"
  puts "    generate             Generate a new Ed25519 keypair"
  puts "    setup <token>        Initial setup with access token"
  puts "    security <mode>      Configure security settings"
  puts "    test-totp <code>     Test TOTP validation"
  puts "    promiscuous <action> Configure promiscuous mode"
  puts "    version, -v, --version  Show version information"
  puts "    help, -h, --help     Show this help message"
  puts ""
  puts "RUN OPTIONS:"
  puts "    --token=<token>      Access token (required for run command)"
  puts "    --debug              Enable debug logging"
  puts ""
  puts "SECURITY MODES:"
  puts "    totp [secret]        Enable TOTP authentication"
  puts "    password [pass]      Enable password authentication"
  puts "    none                 Disable security"
  puts ""
  puts "PROMISCUOUS ACTIONS:"
  puts "    enable               Enable promiscuous mode"
  puts "    disable              Disable promiscuous mode"
  puts "    status               Show promiscuous status"
  puts "    auth <password|totp> Set auth mode for promiscuous operations"
  puts ""
  puts "EXAMPLES:"
  puts "    # Generate new keypair"
  puts "    gentility generate"
  puts "    "
  puts "    # Initial setup"
  puts "    gentility setup <generated_private_key>"
  puts "    "
  puts "    # Configure security"
  puts "    gentility security totp"
  puts "    gentility security password mypass"
  puts "    "
  puts "    # Run agent"
  puts "    gentility run --token=<your_private_key>"
  puts "    gentility start --debug"
  puts "    "
  puts "    # Check status"
  puts "    gentility status"
  puts "    gentility version"
  puts ""
  puts "CONFIGURATION:"
  puts "    Config file: #{get_config_path}"
  puts "    Service: sudo systemctl start gentility"
  puts ""
end

def main
  # Show help if no arguments or help requested
  if ARGV.empty? || ARGV[0].in?(["help", "--help", "-h"])
    show_help
    exit 0
  end

  # Show version if version requested
  if ARGV[0].in?(["version", "--version", "-v"])
    show_version
    exit 0
  end

  # Check for generate command
  if ARGV[0] == "generate"
    generate_keypair
    exit 0
  end

  # Check for setup command
  if ARGV[0] == "setup"
    if ARGV.size >= 2
      setup_config(ARGV[1])
      exit 0
    else
      puts "Usage: #{PROGRAM_NAME} setup <token>"
      puts ""
      puts "Initializes the agent with your Gentility AI access token and creates"
      puts "the configuration file at #{get_config_path}"
      puts ""
      puts "Arguments:"
      puts "  <token>    Your Gentility AI access token (starts with 'gnt_')"
      puts ""
      puts "Example:"
      puts "  #{PROGRAM_NAME} setup gnt_1234567890abcdef"
      puts ""
      puts "After setup, start the service with:"
      puts "  sudo systemctl start gentility"
      exit 1
    end
  end

  # Check for security setup commands
  if ARGV.size >= 1
    case ARGV[0]
    when "run", "start"
      # Remove the run/start command and continue with normal parsing
      ARGV.shift
    when "status"
      show_status
      exit 0
    when "security"
      if ARGV.size >= 2
        mode = ARGV[1]
        value = ARGV.size >= 3 ? ARGV[2] : nil
        setup_security(mode, value)
      else
        puts "Usage: #{PROGRAM_NAME} security <mode> [value]"
        puts ""
        puts "Security modes:"
        puts "  totp [secret]     - Enable TOTP authentication (generates secret if not provided)"
        puts "  password [pass]   - Enable password authentication (prompts if not provided)"
        puts "  none             - Disable security"
        puts ""
        puts "Examples:"
        puts "  #{PROGRAM_NAME} security totp"
        puts "  #{PROGRAM_NAME} security password mySecretPass123"
        puts "  #{PROGRAM_NAME} security none"
        exit 1
      end
    when "test-totp"
      if ARGV.size >= 2
        code = ARGV[1]
        test_totp_validation(code)
      else
        puts "Usage: #{PROGRAM_NAME} test-totp <6-digit-code>"
        puts ""
        puts "Tests TOTP validation with the configured secret."
        puts "Get a code from your authenticator app and test it."
        exit 1
      end
    when "promiscuous"
      if ARGV.size >= 2
        action = ARGV[1]
        case action
        when "enable"
          set_promiscuous_mode(true)
        when "disable"
          set_promiscuous_mode(false)
        when "status"
          show_promiscuous_status
        when "auth"
          if ARGV.size >= 3
            mode = ARGV[2]
            set_promiscuous_auth_mode(mode)
          else
            puts "Usage: #{PROGRAM_NAME} promiscuous auth <password|totp>"
            exit 1
          end
        else
          puts "Usage: #{PROGRAM_NAME} promiscuous <enable|disable|status|auth>"
          puts ""
          puts "Commands:"
          puts "  enable       - Enable promiscuous mode"
          puts "  disable      - Disable promiscuous mode"
          puts "  status       - Show current promiscuous mode status"
          puts "  auth <mode>  - Set promiscuous auth mode (password or totp)"
          exit 1
        end
      else
        puts "Usage: #{PROGRAM_NAME} promiscuous <enable|disable|status|auth>"
        exit 1
      end
    else
      puts "Unknown command: #{ARGV[0]}"
      puts ""
      puts "Available commands: run, start, status, setup, security, test-totp, promiscuous, version, help"
      puts "For detailed help: gentility help or gentility -h"
      exit 1
    end
  end

  access_key, server_url, nickname, environment, debug = parse_arguments

  agent = GentilityAgent.new(access_key, server_url, nickname, environment, debug)

  # Handle graceful shutdown
  Signal::INT.trap do
    puts ""
    puts "Received SIGINT, shutting down gracefully..."
    agent.stop
    exit 0
  end

  Signal::TERM.trap do
    puts ""
    puts "Received SIGTERM, shutting down gracefully..."
    agent.stop
    exit 0
  end

  agent.start
end

# Only run main when not in spec mode
main unless ENV["CRYSTAL_SPEC"]? == "true"
