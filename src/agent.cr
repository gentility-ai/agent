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
require "uri"
require "process"
require "file"
require "crotp"
require "qr-code"
require "yaml"
require "ed25519"
require "base58"
require "crypto/subtle"
require "openssl"
require "base64"
require "socket"

# Agent modules
require "./agent/oauth"

require "./agent/security"
require "./agent/crypto"
require "./agent/config"
require "./agent/database"
require "./agent/cli"
require "./agent/fs"

# Read version from VERSION file at compile time
VERSION = {{ read_file("VERSION").strip }}

class GentilityAgent
  @websocket : HTTP::WebSocket?
  @machine_key : String? # Ed25519 private key (if provisioned)
  @oauth_token : String? # OAuth access token (if using OAuth)
  @server_url : String
  @nickname : String
  @environment : String
  @running : Bool = false
  @graceful_shutdown : Bool = false
  @ping_fiber : Fiber?
  @signing_key : Ed25519::SigningKey?
  @public_key : String?
  @x25519_private_key : Bytes?
  @x25519_public_key : Bytes?
  @x25519_shared_secret : Bytes?
  @rpc_server : UNIXServer?

  def initialize(access_key : String, @server_url : String, @nickname : String, @environment : String = "prod")
    # Determine if this is a machine_key or oauth_token based on prefix
    if access_key.starts_with?("genkey-agent-")
      @machine_key = access_key
      @oauth_token = nil
      @signing_key = nil
      @public_key = nil
      puts "Using machine key authentication" if CLI.debug_mode
    else
      @machine_key = nil
      @oauth_token = access_key
      @signing_key = nil
      @public_key = nil
      puts "Using OAuth token authentication" if CLI.debug_mode
    end

    load_security_config
    load_x25519_keys
  end

  private def load_x25519_keys
    # Load ed25519_seed_key from config and derive X25519 keypair
    config_file = AgentConfig.get_config_path
    config = AgentConfig.load_config_from_file(config_file)

    if config && (seed_key_b58 = config["ed25519_seed_key"]?.try(&.as_s?))
      begin
        seed_bytes = Base58.decode(seed_key_b58).to_slice

        if seed_bytes.size != 32
          puts "Warning: Invalid ed25519_seed_key size (#{seed_bytes.size} bytes, expected 32)" if CLI.debug_mode
          return
        end

        # Derive X25519 keypair from Ed25519 seed
        @x25519_private_key, @x25519_public_key = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_bytes)

        puts "X25519 keypair derived from ed25519_seed_key" if CLI.debug_mode
        puts "X25519 Public Key: #{Base64.strict_encode(@x25519_public_key.not_nil!)}" if CLI.debug_mode
      rescue ex
        puts "Warning: Failed to load X25519 keys: #{ex.message}" if CLI.debug_mode
      end
    else
      puts "No ed25519_seed_key found in config - secure query features will be unavailable" if CLI.debug_mode
    end
  end

  private def load_security_config
    config_file = AgentConfig.get_config_path
    config = AgentConfig.load_config_from_file(config_file)
    return Security.configure("none", nil, nil, 1800, true, true, "password", true, 5, "temporary", 900) unless config

    # Handle empty/nil config
    config_hash = config.as_h?
    return Security.configure("none", nil, nil, 1800, true, true, "password", true, 5, "temporary", 900) unless config_hash

    # Support both YAML security section and legacy flat keys
    # Handle case where security: exists but is nil/empty
    security_any = config["security"]?
    security_config = (security_any && security_any.as_h?) ? security_any : config

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

    # Load rate limiting config (nested under security.rate_limiting or flat)
    # Handle case where rate_limiting: exists but is nil/empty
    rate_limiting_any = security_config["rate_limiting"]?
    rate_limiting_config = (rate_limiting_any && rate_limiting_any.as_h?) ? rate_limiting_any : security_config

    rate_limiting_enabled = rate_limiting_config["enabled"]?.try(&.as_bool?) || true
    max_attempts = rate_limiting_config["max_attempts"]?.try(&.as_i?) || 5
    lockout_mode = rate_limiting_config["lockout_mode"]?.try(&.as_s?) || "temporary"
    lockout_duration = rate_limiting_config["lockout_duration"]?.try(&.as_i?) || 900

    Security.configure(mode, password, totp_secret, timeout, extendable, promiscuous_enabled, promiscuous_auth_mode, rate_limiting_enabled, max_attempts, lockout_mode, lockout_duration)

    # Load persisted lockout state if exists
    locked_out = rate_limiting_config["locked_out"]?.try(&.as_bool?) || false
    lockout_until_ts = rate_limiting_config["lockout_until"]?.try(&.as_f?)

    if locked_out
      lockout_until = lockout_until_ts ? Time.unix(lockout_until_ts.to_i64) : nil
      Security.restore_lockout(lockout_until)
    end
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

  private def save_security_config(mode : String, password : String?, totp_secret : String?, timeout : Int32, extendable : Bool, rate_limiting_lockout : Hash(String, Bool | Float64 | Nil)? = nil)
    config_file = AgentConfig.get_config_path

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

    # Add rate_limiting section if lockout data provided
    if rate_limiting_lockout
      rl_hash = {} of YAML::Any => YAML::Any
      rl_hash[YAML::Any.new("locked_out")] = YAML::Any.new(rate_limiting_lockout["locked_out"].as(Bool))
      if lockout_until_val = rate_limiting_lockout["lockout_until"]
        if lockout_until_val.is_a?(Float64)
          rl_hash[YAML::Any.new("lockout_until")] = YAML::Any.new(lockout_until_val)
        end
      end
      security_hash[YAML::Any.new("rate_limiting")] = YAML::Any.new(rl_hash)
    end

    config_hash[YAML::Any.new("security")] = YAML::Any.new(security_hash)

    # Write updated config
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o640)
  rescue ex : Exception
    puts "Warning: Could not save security configuration to file: #{ex.message}"
  end

  private def save_security_config_clear_lockout
    # Save config with lockout cleared
    lockout_data = {"locked_out" => false, "lockout_until" => nil}
    save_security_config(Security.mode, nil, nil, Security.unlock_timeout, Security.extendable?, lockout_data)
  end

  private def send_lockout_notification
    # SERVER INTEGRATION NOTE:
    # When the agent enters lockout state, it sends a security_lockout message.
    # The server should:
    # 1. Display warning in UI: "Agent locked due to failed auth attempts"
    # 2. For temporary lockout: show "locked_until" timestamp to user
    # 3. For permanent lockout: show "Manual intervention required" message
    # 4. Stop sending security_unlock commands until lockout clears
    # 5. Display lockout status in agent status view

    lockout_msg = {
      "type"            => "security_lockout",
      "lockout_mode"    => Security.lockout_mode,
      "failed_attempts" => Security.failed_attempt_count,
      "timestamp"       => Time.utc.to_unix_f,
    }

    if lockout_until = Security.lockout_until
      lockout_msg = lockout_msg.merge({"lockout_until" => lockout_until.to_unix_f})
    end

    send_message(lockout_msg)
  end

  def start
    config_file = AgentConfig.get_config_path
    puts "Starting Gentility Agent v#{VERSION}..."
    puts "Config: #{config_file}#{File.exists?(config_file) ? "" : " (not found)"}"
    puts "Nickname: #{@nickname}"
    puts "Environment: #{@environment}"
    puts "Server: #{@server_url}"
    puts "Debug mode: #{CLI.debug_mode ? "enabled" : "disabled"}"
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
    @graceful_shutdown = true

    # The ping fiber will stop naturally when @running becomes false

    # Close WebSocket
    @websocket.try(&.close)

    # Stop RPC server
    @rpc_server.try(&.close)
  end

  def reload_security_config
    puts "Reloading security configuration..."
    load_security_config
    puts "Security configuration reloaded"
  end

  private def debug_log(message : String)
    if CLI.debug_mode
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
      path: "/agent/websocket",
      query: URI::Params.build do |params|
        if @machine_key
          # Machine key mode: send the full machine key
          params.add "machine_key", @machine_key.not_nil!
        elsif @oauth_token
          # OAuth mode: send OAuth token
          params.add "oauth_token", @oauth_token.not_nil!
        end
        params.add "version", VERSION
        params.add "security_mode", Security.mode
        params.add "security_enabled", (Security.mode != "none").to_s
        params.add "security_active", Security.unlocked?.to_s

        # Add X25519 public key for secure credential exchange
        if @x25519_public_key
          params.add "x25519_pubkey", Base64.strict_encode(@x25519_public_key.not_nil!)
        end
      end
    )

    puts "Connecting to #{ws_uri}..."

    # Connect to WebSocket
    @websocket = HTTP::WebSocket.new(ws_uri)

    # Set up message handler
    @websocket.not_nil!.on_message do |message|
      handle_message(message)
    end

    @websocket.not_nil!.on_close do |close_code, message|
      unless @graceful_shutdown
        puts "WebSocket closed: #{close_code} - #{message}"
      end
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

      # Start Unix socket RPC server for fs commands
      start_rpc_server

      # Send initial status
      send_status
    else
      raise "Failed to establish WebSocket connection"
    end
  end

  private def handle_message(message : String)
    debug_log("← Received message (#{message.size} bytes)")

    begin
      # Parse JSON
      data = JSON.parse(message)
      debug_log("← Parsed: #{data.inspect}")

      # Handle the parsed JSON data
      handle_parsed_message(data)
    rescue ex : Exception
      puts "Error parsing JSON message: #{ex.message}"
      debug_log("← Parse error: #{ex.message}")
    end
  end

  private def handle_parsed_message(msg : JSON::Any)
    case msg["type"]?.try(&.to_s)
    when "welcome"
      puts "✅ Connected to server!"
      machine_id = msg["machine_id"]?.try(&.to_s)
      puts "Machine ID: #{machine_id}" if machine_id

      # Handle server's X25519 public key and derive shared secret
      if server_x25519_b64 = msg["x25519_pubkey"]?.try(&.to_s)
        if @x25519_private_key
          begin
            server_pubkey = Base64.decode(server_x25519_b64)

            if server_pubkey.size != 32
              puts "Warning: Invalid server X25519 public key size (got #{server_pubkey.size} bytes)" if CLI.debug_mode
            else
              # Derive shared secret using ECDH
              @x25519_shared_secret = AgentCrypto.x25519_ecdh(@x25519_private_key.not_nil!, server_pubkey)

              if CLI.debug_mode
                shared_secret_b64 = Base64.strict_encode(@x25519_shared_secret.not_nil!)
                # Validate the shared secret
                if @x25519_shared_secret.not_nil!.all? { |b| b == 0 }
                  puts "⚠️  Warning: Shared secret is all zeros (ECDH may have failed)"
                elsif @x25519_shared_secret.not_nil!.size != 32
                  puts "⚠️  Warning: Shared secret has invalid size: #{@x25519_shared_secret.not_nil!.size} bytes"
                else
                  puts "✅ Shared secret established for secure credential exchange"
                  puts "   Shared Secret (base64): #{shared_secret_b64}"
                  puts "   Size: #{@x25519_shared_secret.not_nil!.size} bytes"
                end
              end
            end
          rescue ex
            puts "Warning: Failed to derive shared secret: #{ex.message}" if CLI.debug_mode
          end
        else
          puts "Warning: Server sent X25519 public key but agent has no X25519 private key" if CLI.debug_mode
        end
      end
    when "error"
      # Handle error messages from server
      error_code = msg["error"]?.try(&.to_s)
      error_message = msg["message"]?.try(&.to_s) || "Unknown error"

      puts ""
      puts "❌ Server Error: #{error_message}"

      # Handle specific error cases
      case error_code
      when "token_expired", "invalid_token"
        puts ""
        puts "Your OAuth token has expired or is invalid."
        puts "Please re-authenticate by running:"
        puts "  gentility auth"
        puts ""
        exit 1
      when "insufficient_scope"
        puts ""
        puts "Your OAuth token is missing required scopes."
        puts "Please re-authenticate by running:"
        puts "  gentility auth"
        puts ""
        exit 1
      else
        puts ""
        puts "Error code: #{error_code}" if error_code
        exit 1
      end
    when "ping"
      # Respond to ping with security status
      response = {"type" => "pong", "timestamp" => Time.utc.to_unix_f}
      response = response.merge(Security.status)
      send_message(response)
    when "pong"
      # Handle pong response (server responding to our ping)
      if CLI.debug_mode
        timestamp = msg["timestamp"]?.try(&.as_f?)
        if timestamp
          # Calculate round-trip time if we want
          current_time = Time.utc.to_unix_f
          rtt = current_time - timestamp
          puts "Received pong from server (RTT: #{(rtt * 1000).round(2)}ms)" if rtt > 0
        else
          puts "Received pong from server"
        end
      end
    when "command"
      handle_command(msg)
    else
      puts "Unknown message type: #{msg["type"]?}"
      puts "Full message: #{msg}"
    end
  end

  private def handle_command(msg : JSON::Any)
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

  private def handle_ecdh_test(msg : JSON::Any)
    puts "Received ECDH test request"

    version = msg["v"]?.try(&.as_i?) || 1
    cleartext = msg["cleartext"]?.try(&.to_s)
    ciphertext_b64 = msg["ciphertext"]?.try(&.to_s)

    unless cleartext && ciphertext_b64
      puts "Error: Missing cleartext or ciphertext in ecdh_test"
      return
    end

    unless @x25519_shared_secret
      puts "Error: No shared secret established - cannot perform ECDH test"
      send_message({
        "type" => "ecdh_test_response",
        "v" => version,
        "success" => false,
        "error" => "No shared secret established"
      })
      return
    end

    begin
      # Decrypt using the shared secret
      decrypted = AgentCrypto.decrypt_with_shared_secret(@x25519_shared_secret.not_nil!, ciphertext_b64)

      # Extract IV from ciphertext
      ciphertext = Base64.decode(ciphertext_b64)
      iv = ciphertext[0...16]
      iv_b64 = Base64.strict_encode(iv)

      # Check if decrypted matches cleartext
      success = (decrypted == cleartext)

      puts "ECDH Test: #{success ? "✅ SUCCESS" : "❌ FAILED"}"
      puts "  Expected: #{cleartext}"
      puts "  Got: #{decrypted}"

      send_message({
        "type" => "ecdh_test_response",
        "v" => version,
        "success" => success,
        "iv" => iv_b64,
        "payload" => decrypted
      })
    rescue ex
      puts "ECDH Test Failed: #{ex.message}"
      send_message({
        "type" => "ecdh_test_response",
        "v" => version,
        "success" => false,
        "error" => ex.message || "Decryption failed"
      })
    end
  end

  private def execute_command(command : String, params : JSON::Any?)
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
      return {"error" => "Machine key required for encrypted credentials"} unless @signing_key
      Security.extend_unlock

      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if db_target_id && query
        # Load credentials from encrypted storage
        config_file = AgentConfig.get_config_path
        creds_json = AgentCrypto.load_credentials(config_file, db_target_id, @signing_key.not_nil!)

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
      return {"error" => "Machine key required for encrypted credentials"} unless @signing_key
      Security.extend_unlock

      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if db_target_id && query
        # Load credentials from encrypted storage
        config_file = AgentConfig.get_config_path
        creds_json = AgentCrypto.load_credentials(config_file, db_target_id, @signing_key.not_nil!)

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
      unless credential
        return {"error" => "Missing credential parameter"}
      end

      # Check if locked out
      if Security.locked_out?
        if Security.lockout_until
          # Temporary lockout
          locked_for = (Security.lockout_until.not_nil! - Time.utc).total_seconds.to_i
          return {
            "error"        => "Agent locked due to too many failed attempts",
            "lockout_mode" => "temporary",
            "locked_until" => Security.lockout_until.not_nil!.to_unix_f,
            "locked_for"   => locked_for,
          }
        else
          # Permanent lockout
          return {
            "error"        => "Agent permanently locked due to too many failed attempts",
            "lockout_mode" => "permanent",
            "message"      => "Manual intervention required: restart agent or edit config file",
          }
        end
      end

      # Check if in backoff period
      unless Security.can_attempt?
        retry_after = Security.time_until_next_attempt
        attempts_remaining = Security.max_attempts - Security.failed_attempt_count
        return {
          "error"              => "Too many failed attempts",
          "retry_after"        => retry_after,
          "attempts_remaining" => attempts_remaining,
        }
      end

      # Attempt unlock
      if Security.unlock(credential)
        send_status # Send updated security status

        # If we just recovered from lockout, clear persisted state
        if Security.was_locked_out?
          save_security_config_clear_lockout
        end

        {"success" => true, "message" => "Agent unlocked successfully"}
      else
        # Invalid credentials
        attempts_remaining = Security.max_attempts - Security.failed_attempt_count

        # Check if this failure triggered lockout
        if Security.locked_out?
          # Persist lockout state
          lockout_data = Security.persist_lockout
          save_security_config(Security.mode, nil, nil, Security.unlock_timeout, Security.extendable?, lockout_data)
          send_lockout_notification

          if Security.lockout_until
            locked_for = (Security.lockout_until.not_nil! - Time.utc).total_seconds.to_i
            return {
              "error"        => "Agent locked due to too many failed attempts",
              "lockout_mode" => "temporary",
              "locked_until" => Security.lockout_until.not_nil!.to_unix_f,
              "locked_for"   => locked_for,
            }
          else
            return {
              "error"        => "Agent permanently locked due to too many failed attempts",
              "lockout_mode" => "permanent",
              "message"      => "Manual intervention required",
            }
          end
        end

        {"error" => "Invalid credentials", "attempts_remaining" => attempts_remaining}
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
      return {"error" => "Machine key required for credential storage"} unless @signing_key
      # Store encrypted database credentials on the agent
      db_target_id = params.try(&.["db_target_id"]?.try(&.to_s))
      credentials = params.try(&.["credentials"]?.try(&.to_s))

      if db_target_id && credentials
        begin
          config_file = AgentConfig.get_config_path
          AgentCrypto.store_credentials(config_file, db_target_id, credentials, @signing_key.not_nil!)
          {"success" => true, "message" => "Credentials stored securely"}
        rescue ex : Exception
          {"error" => "Failed to store credentials: #{ex.message}"}
        end
      else
        {"error" => "Missing db_target_id or credentials parameter"}
      end
    when "secure_psql_query"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      return {"error" => "Shared secret required for secure queries"} unless @x25519_shared_secret
      Security.extend_unlock

      encrypted_payload = params.try(&.["encrypted_payload"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if encrypted_payload && query
        begin
          # Decrypt credentials using shared secret (IV is embedded in payload)
          creds_json = AgentCrypto.decrypt_with_shared_secret(
            @x25519_shared_secret.not_nil!,
            encrypted_payload
          )

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
            {"error" => "Invalid decrypted credentials"}
          end
        rescue ex : Exception
          {"error" => "Failed to decrypt credentials: #{ex.message}"}
        end
      else
        {"error" => "Missing required parameters: encrypted_payload, query"}
      end
    when "secure_mysql_query"
      return {"error" => "Agent unlock required for database queries"} unless Security.unlocked?
      return {"error" => "Shared secret required for secure queries"} unless @x25519_shared_secret
      Security.extend_unlock

      encrypted_payload = params.try(&.["encrypted_payload"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if encrypted_payload && query
        begin
          # Decrypt credentials using shared secret (IV is embedded in payload)
          creds_json = AgentCrypto.decrypt_with_shared_secret(
            @x25519_shared_secret.not_nil!,
            encrypted_payload
          )

          # Parse credentials JSON
          creds = JSON.parse(creds_json)
          host = creds["host"]?.try(&.as_s)
          port = creds["port"]?.try(&.as_i)
          dbname = creds["database"]?.try(&.as_s)

          if host && port && dbname
            execute_mysql_query(host, port, dbname, query)
          else
            {"error" => "Invalid decrypted credentials"}
          end
        rescue ex : Exception
          {"error" => "Failed to decrypt credentials: #{ex.message}"}
        end
      else
        {"error" => "Missing required parameters: encrypted_payload, query"}
      end
    when "ecdh_test"
      # Test ECDH encryption/decryption
      version = params.try(&.["version"]?.try(&.as_i?)) || 1
      cleartext = params.try(&.["cleartext"]?.try(&.to_s))
      ciphertext_b64 = params.try(&.["ciphertext"]?.try(&.to_s))

      unless cleartext && ciphertext_b64
        return {"error" => "Missing required parameters: cleartext, ciphertext"}
      end

      unless @x25519_shared_secret
        return {"error" => "No shared secret established - ECDH not available"}
      end

      begin
        # Decrypt using the shared secret (expects base64 input)
        decrypted = AgentCrypto.decrypt_with_shared_secret(@x25519_shared_secret.not_nil!, ciphertext_b64)

        # Extract IV (first 16 bytes of decoded ciphertext)
        ciphertext = Base64.decode(ciphertext_b64)
        iv = ciphertext[0...16]
        iv_b64 = Base64.strict_encode(iv)

        # Check if decrypted text matches cleartext
        success = (decrypted == cleartext)

        {
          "v"       => version,
          "success" => success,
          "iv"      => iv_b64,
          "payload" => decrypted,
        }
      rescue ex
        {
          "v"       => version,
          "success" => false,
          "error"   => ex.message || "Decryption failed",
        }
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

  private def check_capabilities(capabilities_list : Array(JSON::Any))
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
    puts "Executing: #{cmd}" if CLI.debug_mode

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
    AgentDatabase.execute_psql_query(host, port, dbname, query, username, password)
  end

  private def execute_mysql_query(host : String, port : Int32, dbname : String, query : String)
    AgentDatabase.execute_mysql_query(host, port, dbname, query)
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

        # Send ping every 60 seconds
        sleep 60.seconds

        if @websocket && !@websocket.not_nil!.closed?
          send_message({"type" => "ping", "timestamp" => Time.utc.to_unix_f})
        end
      end
    end
  end

  # Helper method to send a message as JSON
  private def send_message(data : Hash)
    debug_log("→ Sending: #{data.inspect}")

    websocket = @websocket
    return unless websocket && !websocket.closed?

    begin
      json = data.to_json
      debug_log("→ Sending JSON message (#{json.size} bytes)")
      websocket.send(json)
    rescue ex : Exception
      puts "Error sending message: #{ex.message}"
      debug_log("→ Send error: #{ex.message}")
    end
  end

  private def start_rpc_server
    socket_path = AgentFS::SOCKET_PATH

    # Clean up stale socket
    File.delete(socket_path) if File.exists?(socket_path)

    # Ensure parent directory exists
    Dir.mkdir_p(socket_path.parent)

    # Create Unix socket server
    @rpc_server = UNIXServer.new(socket_path.to_s)

    # Spawn fiber to handle RPC requests
    spawn do
      # Create storage and RPC handler
      storage = AgentFS::Storage.new(AgentFS::BASE_DIR.to_s)
      rpc_handler = AgentFS::RPCServer.new(storage)

      while @running
        if server = @rpc_server
          if client = server.accept?
            spawn handle_rpc_client(client, rpc_handler)
          end
        else
          break
        end
      end
    rescue ex : Exception
      puts "RPC server error: #{ex.message}" unless @graceful_shutdown
    end

    puts "RPC server listening on #{socket_path}"
  rescue ex : Exception
    puts "Failed to start RPC server: #{ex.message}"
  end

  private def handle_rpc_client(client : UNIXSocket, rpc : AgentFS::RPCServer)
    request = client.gets
    return unless request

    response = rpc.handle(request)
    client.puts(response)
  ensure
    client.close
  end
end

# Only run main when not in spec mode
main() unless ENV["CRYSTAL_SPEC"]? == "true"
