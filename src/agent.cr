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

# Agent modules
require "./agent/oauth"

require "./agent/security"
require "./agent/crypto"
require "./agent/config"
require "./agent/database"
require "./agent/cli"

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
  @ping_fiber : Fiber?
  @debug : Bool = false
  @signing_key : Ed25519::SigningKey?
  @public_key : String?

  def initialize(access_key : String, @server_url : String, @nickname : String, @environment : String = "prod", @debug : Bool = false)
    # Try to parse as Ed25519 key first (machine_key)
    # If that fails, treat it as OAuth token
    begin
      @signing_key = AgentCrypto.parse_private_key(access_key)
      @public_key = AgentCrypto.public_key_base58(@signing_key.not_nil!)
      @machine_key = access_key
      @oauth_token = nil
      puts "Using machine key authentication" if @debug
      puts "Agent Public Key: #{@public_key}" if @debug
    rescue
      # Not an Ed25519 key, treat as OAuth token
      @signing_key = nil
      @public_key = nil
      @machine_key = nil
      @oauth_token = access_key
      puts "Using OAuth token authentication" if @debug
    end

    load_security_config
  end

  private def load_security_config
    config_file = AgentConfig.get_config_path
    config = AgentConfig.load_config_from_file(config_file)
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
        if @public_key
          # Machine key mode: send public key
          params.add "access_key", @public_key.not_nil!
        elsif @oauth_token
          # OAuth mode: send OAuth token
          params.add "oauth_token", @oauth_token.not_nil!
        end
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
      puts "✅ Connected to server!"
      machine_id = msg["machine_id"]?.try(&.to_s)
      puts "Machine ID: #{machine_id}" if machine_id
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

# Only run main when not in spec mode
main unless ENV["CRYSTAL_SPEC"]? == "true"
