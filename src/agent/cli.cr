require "crotp"
require "qr-code"
require "base58"
require "yaml"
require "http/web_socket"
require "openssl"
require "./config"
require "./crypto"
require "./oauth"

# CLI functions for the Gentility Agent

module CLI
  @@debug_mode = false

  def self.debug_mode
    @@debug_mode
  end

  def self.debug_mode=(value : Bool)
    @@debug_mode = value
  end
end

# Configuration and argument parsing
def parse_arguments
  # 1. Start with defaults
  access_key = nil
  server_url = nil # Will be set based on environment
  nickname = `hostname`.strip
  environment = "prod"
  debug = false

  # 2. Load configuration from file if it exists
  config_file = AgentConfig.get_config_path
  config = AgentConfig.load_config_from_file(config_file)

  # Apply config file settings (YAML format)
  if config
    # Only accept machine_key (OAuth tokens are never stored)
    access_key = config["machine_key"]?.try(&.as_s?) ||
                 config["access_key"]?.try(&.as_s?) ||
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
  # Check for --token, --debug, and --env arguments
  i = 0
  while i < ARGV.size
    arg = ARGV[i]
    if arg.starts_with?("--token=")
      access_key = arg.split("=", 2)[1]
      i += 1
    elsif arg == "--debug"
      debug = true
      i += 1
    elsif arg == "-e" || arg == "--env"
      if i + 1 < ARGV.size
        environment = ARGV[i + 1]
        i += 2
      else
        i += 1
      end
    else
      i += 1
    end
  end

  # Check for legacy positional arguments (backward compatibility)
  non_token_args = ARGV.reject { |arg| arg.starts_with?("--token=") || arg == "--debug" || arg == "-e" || arg == "--env" || (ARGV.index(arg).try { |idx| idx > 0 && (ARGV[idx - 1] == "-e" || ARGV[idx - 1] == "--env") }) }

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
    puts "❌ ERROR: No machine key found!"
    puts ""
    puts "To authenticate and provision your agent, run:"
    puts "  gentility auth"
    puts ""
    puts "This will:"
    puts "  1. Open your browser for OAuth authentication"
    puts "  2. Connect to the server and provision a machine key"
    puts "  3. Save the key for future connections"
    puts ""
    puts "After authentication, start the agent with:"
    puts "  gentility run"
    puts ""
    puts "For help: gentility help"
    exit 1
  end

  # Set server_url based on environment if not explicitly configured
  unless server_url
    server_url = AgentConfig::ServerURLs.websocket_url(environment)
  end

  {access_key, server_url, nickname, environment}
end

def setup_config(token : String)
  config_file = AgentConfig.get_config_path

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

    # OPTIONAL: Server URL (default: wss://ws.gentility.ai)
    # server_url: wss://ws.gentility.ai

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
  config_file = AgentConfig.get_config_path

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
    AgentConfig.update_config(config_file, "SECURITY_MODE", "totp")
    AgentConfig.update_config(config_file, "SECURITY_TOTP_SECRET", secret)
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
    AgentConfig.update_config(config_file, "SECURITY_MODE", "password")
    AgentConfig.update_config(config_file, "SECURITY_PASSWORD", password)
  when "none"
    puts "🔐 Security Disabled"
    puts "==================="
    puts "Security mode set to none - no authentication required."
    puts ""

    AgentConfig.update_config(config_file, "SECURITY_MODE", "none")
    AgentConfig.remove_config(config_file, ["SECURITY_PASSWORD", "SECURITY_TOTP_SECRET"])
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

def is_ssh_session? : Bool
  # Check for SSH environment variables
  # Note: sudo strips these by default, so we need additional checks

  # Direct SSH check
  return true if ENV.has_key?("SSH_CONNECTION") || ENV.has_key?("SSH_CLIENT") || ENV.has_key?("SSH_TTY")

  # If running under sudo, check if the parent process is SSH
  if ENV.has_key?("SUDO_USER")
    # Check if any parent process is sshd
    begin
      # Get parent processes
      ppid = Process.ppid
      loop do
        break if ppid <= 1

        # Read process command line
        cmdline = File.read("/proc/#{ppid}/cmdline").gsub('\0', ' ').strip rescue ""
        return true if cmdline.includes?("sshd")

        # Get parent of parent
        stat = File.read("/proc/#{ppid}/stat").strip rescue ""
        if match = stat.match(/\d+\s+\([^)]+\)\s+\w+\s+(\d+)/)
          ppid = match[1].to_i
        else
          break
        end
      end
    rescue
      # If we can't check /proc, fall back to other heuristics
    end
  end

  false
end

def run_oauth_flow(environment : String, headless : Bool, debug : Bool, org_id : String?, env_name : String?, nickname : String?)
  # Auto-detect SSH/remote and use appropriate flow
  use_device_flow = is_ssh_session?

  if use_device_flow
    puts "🌐 Remote/SSH session detected - using device code flow"
    puts ""
  end

  puts "🔐 Starting OAuth authentication flow..."
  puts "Environment: #{environment}"
  puts "Debug mode: #{debug ? "enabled" : "disabled"}" if debug
  puts ""

  begin
    # Step 1: Get OAuth token (choose flow based on environment)
    tokens = if use_device_flow
               OAuth::Flow.authenticate_device(environment, debug)
             else
               OAuth::Flow.authenticate(environment, headless, debug)
             end

    oauth_token = tokens.access_token

    puts ""
    puts "✅ OAuth token received"
    puts ""

    # Step 2: Connect to server immediately to provision machine key
    puts "🔗 Connecting to server to provision machine key..."

    server_url = AgentConfig::ServerURLs.websocket_url(environment)

    # Create a temporary agent just to provision the key
    provision_machine_key(oauth_token, server_url, environment, debug, org_id, env_name, nickname)
  rescue ex : Exception
    puts ""
    puts "❌ OAuth authentication failed: #{ex.message}"
    puts ex.backtrace.join("\n") if debug
    exit 1
  end
end

def provision_machine_key(oauth_token : String, server_url : String, environment : String, debug : Bool, org_id : String?, env_name : String?, nickname : String?)
  puts ""

  # Create provisioning context
  provisioner = AgentProvisioner.new(oauth_token, server_url, environment, debug, org_id, env_name, nickname)

  begin
    provisioner.run

    puts ""
    puts "✅ Authentication complete!"
    puts ""
    puts "You can now start the agent with:"
    puts "  gentility run"
    puts "  # Or as a service:"
    puts "  brew services start gentility-agent  # macOS"
    puts "  sudo systemctl start gentility        # Linux"
    exit 0
  rescue ex : Exception
    puts ""
    puts "❌ Provisioning failed: #{ex.message}"
    puts ex.backtrace.join("\n") if debug
    exit 1
  end
end

# Helper class to manage progressive provisioning flow
class AgentProvisioner
  @oauth_token : String
  @server_url : String
  @environment : String
  @debug : Bool
  @org_id : String?
  @env_name : String?
  @nickname : String?
  @websocket : HTTP::WebSocket?
  @provision_channel : Channel(JSON::Any)
  @complete : Bool = false

  def initialize(@oauth_token, @server_url, @environment, @debug, @org_id, @env_name, @nickname)
    @provision_channel = Channel(JSON::Any).new
  end

  private def debug_log(message : String)
    if @debug
      puts "[DEBUG] #{Time.local.to_s("%Y-%m-%d %H:%M:%S")} #{message}"
    end
  end

  def run
    # Connect to WebSocket
    connect_websocket

    # Wait for provisioning_welcome
    msg = wait_for_message(10.seconds)
    unless msg["type"]?.try(&.to_s) == "provisioning_welcome"
      raise "Expected provisioning_welcome, got: #{msg["type"]?}"
    end

    puts "📋 Starting agent provisioning..."
    puts ""

    # Progressive provisioning loop
    selected_org_id = @org_id
    selected_env = @env_name
    selected_nickname = @nickname

    loop do
      # Build provision request
      request = {"type" => "provision_request", "v" => 1} of String => (String | Int32)
      request["organization_id"] = selected_org_id if selected_org_id
      request["environment"] = selected_env if selected_env
      request["nickname"] = selected_nickname if selected_nickname

      # Send request
      send_message(request)

      # Wait for response
      response = wait_for_message(30.seconds)

      case response["type"]?.try(&.to_s)
      when "provision_incomplete"
        missing = response["missing"]?.try(&.to_s)
        options = response["options"]?.try(&.as_a?)

        case missing
        when "organization"
          # Prompt user to select organization
          selected_org_id = prompt_organization(options)
        when "environment"
          # Prompt user to select environment
          selected_env = prompt_environment(options)
        else
          raise "Unknown missing field: #{missing}"
        end
      when "provision_complete"
        # Success! Save machine key
        machine_key = response["machine_key"]?.try(&.to_s)
        raise "No machine_key in provision_complete" unless machine_key

        server_target_id = response["server_target_id"]?.try(&.to_s)
        org_id = response["organization_id"]?.try(&.to_s)
        environment = response["environment"]?.try(&.to_s)
        nickname = response["nickname"]?.try(&.to_s)

        puts "✅ Provisioning complete!"
        puts "   Organization: #{org_id}"
        puts "   Environment: #{environment}"
        puts "   Nickname: #{nickname}"
        puts "   Server Target ID: #{server_target_id}"
        puts ""
        puts "💾 Saving machine key..."

        save_machine_key(machine_key, org_id, environment, nickname)

        @complete = true
        @websocket.try(&.close)
        break
      when "error"
        error_type = response["error"]?.try(&.to_s) || "unknown_error"
        error_msg = response["message"]?.try(&.to_s) || "Unknown error"

        puts ""
        puts "❌ Provisioning failed: #{error_type}"
        puts "   #{error_msg}"
        puts ""
        puts "This is a server-side error. Please contact support if the issue persists."
        puts ""

        @websocket.try(&.close)
        return
      else
        raise "Unexpected response type: #{response["type"]?}"
      end
    end
  end

  private def connect_websocket
    uri = URI.parse(@server_url)
    ws_uri = URI.new(
      scheme: (uri.scheme == "https" || uri.scheme == "wss") ? "wss" : "ws",
      host: uri.host,
      port: uri.port,
      path: "/agent/websocket",
      query: URI::Params.build do |params|
        params.add "oauth_token", @oauth_token
        params.add "version", VERSION
      end
    )

    debug_log("Connecting to WebSocket: #{ws_uri.host}:#{ws_uri.port}#{ws_uri.path}")

    @websocket = HTTP::WebSocket.new(ws_uri)

    # Set up JSON message handler
    @websocket.not_nil!.on_message do |message|
      begin
        debug_log("← Received message (#{message.size} bytes)")
        data = JSON.parse(message)
        debug_log("← Parsed: #{data.inspect}")
        @provision_channel.send(data)
      rescue ex
        puts "Error parsing message: #{ex.message}"
        debug_log("← Parse error: #{ex.message}")
      end
    end

    @websocket.not_nil!.on_close do |code, message|
      debug_log("WebSocket closed: #{code} - #{message}")
    end

    # Start WebSocket in background
    spawn do
      @websocket.not_nil!.run
    end

    sleep 1.second # Give connection time to establish
    debug_log("WebSocket connection established")
  end

  private def wait_for_message(timeout : Time::Span) : JSON::Any
    select
    when msg = @provision_channel.receive
      return msg
    when timeout(timeout)
      raise "Timeout waiting for server response"
    end
  end

  private def send_message(data : Hash)
    ws = @websocket
    return unless ws && !ws.closed?

    debug_log("→ Sending: #{data.inspect}")
    json = data.to_json
    debug_log("→ Sending JSON message (#{json.size} bytes)")
    ws.send(json)
  end

  private def prompt_organization(options : Array(JSON::Any)?) : String
    # Non-interactive mode
    if org_id = @org_id
      return org_id
    end

    raise "No organizations available" unless options && !options.empty?

    puts "Select an organization:"
    puts ""

    orgs = options.map do |opt|
      {
        "id"   => opt["id"].as_s,
        "name" => opt["name"].as_s,
        "slug" => opt["slug"]?.try(&.as_s?),
      }
    end

    orgs.each_with_index do |org, idx|
      puts "  #{idx + 1}. #{org["name"]} (#{org["slug"]})"
    end

    puts ""
    print "Enter selection (1-#{orgs.size}): "

    selection = gets.try(&.strip.to_i?) || 0

    if selection < 1 || selection > orgs.size
      raise "Invalid selection: #{selection}"
    end

    selected = orgs[selection - 1]
    puts "Selected: #{selected["name"]}"
    puts ""

    selected["id"].not_nil!
  end

  private def prompt_environment(options : Array(JSON::Any)?) : String
    # Non-interactive mode
    if env_name = @env_name
      return env_name
    end

    raise "No environments available" unless options && !options.empty?

    puts "Select an environment:"
    puts ""

    envs = options.map do |opt|
      {
        "value" => opt["value"].as_s,
        "label" => opt["label"].as_s,
      }
    end

    envs.each_with_index do |env, idx|
      puts "  #{idx + 1}. #{env["label"]}"
    end

    puts ""
    print "Enter selection (1-#{envs.size}): "

    selection = gets.try(&.strip.to_i?) || 0

    if selection < 1 || selection > envs.size
      raise "Invalid selection: #{selection}"
    end

    selected = envs[selection - 1]
    puts "Selected: #{selected["label"]}"
    puts ""

    selected["value"].not_nil!
  end

  private def save_machine_key(machine_key : String, org_id : String?, environment : String?, nickname : String?)
    config_file = AgentConfig.get_config_path

    # Check write permissions early before doing any work
    config_dir = File.dirname(config_file)

    if File.exists?(config_file)
      unless File::Info.writable?(config_file)
        raise "Permission denied: Cannot write to #{config_file}. Try running with sudo."
      end
    else
      unless File::Info.writable?(config_dir)
        raise "Permission denied: Cannot write to directory #{config_dir}. Try running with sudo."
      end
    end

    # Read existing config or create new one
    config = if File.exists?(config_file)
               YAML.parse(File.read(config_file))
             else
               YAML.parse("{}")
             end

    config_hash = config.as_h? || {} of YAML::Any => YAML::Any

    # Generate ed25519_seed_key for X25519 key exchange if not already present
    unless config_hash.has_key?(YAML::Any.new("ed25519_seed_key"))
      # Generate new Ed25519 seed (32 random bytes)
      seed_bytes = Random::Secure.random_bytes(32)
      seed_base58 = Base58.encode(seed_bytes)
      config_hash[YAML::Any.new("ed25519_seed_key")] = YAML::Any.new(seed_base58)
      puts "   Generated ed25519_seed_key for secure credential exchange"
    end

    # Save machine key and metadata
    config_hash[YAML::Any.new("machine_key")] = YAML::Any.new(machine_key)
    config_hash[YAML::Any.new("organization_id")] = YAML::Any.new(org_id) if org_id
    config_hash[YAML::Any.new("environment")] = YAML::Any.new(environment) if environment
    config_hash[YAML::Any.new("nickname")] = YAML::Any.new(nickname) if nickname

    # Write config
    File.write(config_file, config_hash.to_yaml)
    File.chmod(config_file, 0o600)
  end
end

def test_totp_validation(code : String)
  config_file = AgentConfig.get_config_path
  config = AgentConfig.load_config_from_file(config_file) || {} of String => String

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
  config_file = AgentConfig.get_config_path
  config = AgentConfig.load_config_from_file(config_file) || {} of String => String

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
  config_file = AgentConfig.get_config_path

  AgentConfig.update_config(config_file, "PROMISCUOUS_ENABLED", enabled.to_s)

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

  config_file = AgentConfig.get_config_path

  AgentConfig.update_config(config_file, "PROMISCUOUS_AUTH_MODE", mode)

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

def clear_lockout_from_cli
  config_file = AgentConfig.get_config_path

  unless File.exists?(config_file)
    puts "❌ Error: Config file not found: #{config_file}"
    exit 1
  end

  # Read config
  config = YAML.parse(File.read(config_file))
  config_hash = config.as_h? || {} of YAML::Any => YAML::Any

  # Check if security section exists
  unless config_hash.has_key?(YAML::Any.new("security"))
    puts "🔐 No security configuration found"
    exit 0
  end

  security_hash = config_hash[YAML::Any.new("security")].as_h? || {} of YAML::Any => YAML::Any

  # Check if rate_limiting section exists with lockout
  if rl = security_hash[YAML::Any.new("rate_limiting")]?.try(&.as_h?)
    if rl[YAML::Any.new("locked_out")]?.try(&.as_bool?)
      # Remove lockout state
      rl.delete(YAML::Any.new("locked_out"))
      rl.delete(YAML::Any.new("lockout_until"))

      # Write updated config
      File.write(config_file, config_hash.to_yaml)
      File.chmod(config_file, 0o600)

      puts "🔐 Lockout Cleared"
      puts "================="
      puts "Lockout state removed from configuration."
      puts ""

      # Try to signal running agent
      begin
        # Find agent PID
        result = `pgrep -f 'gentility.*run|gentility-agent'`.strip
        if !result.empty?
          pids = result.split("\n")
          pids.each do |pid|
            puts "Signaling agent process (PID #{pid}) to reload config..."
            Process.signal(Signal::HUP, pid.to_i)
          end
          puts ""
          puts "✅ Agent notified to reload configuration"
        else
          puts "⚠️  No running agent found"
          puts "If agent is running, restart it to apply changes:"
          puts "  sudo systemctl restart gentility"
        end
      rescue ex : Exception
        puts "⚠️  Could not signal agent: #{ex.message}"
        puts "Restart agent to apply changes:"
        puts "  sudo systemctl restart gentility"
      end
    else
      puts "✅ Agent is not locked out"
    end
  else
    puts "✅ Agent is not locked out"
  end

  exit 0
rescue ex : Exception
  puts "❌ Error: #{ex.message}"
  exit 1
end

def show_status
  puts "Gentility Agent v#{VERSION}"
  puts "==================#{("=" * VERSION.size)}"
  puts ""

  config_file = AgentConfig.get_config_path
  config = AgentConfig.load_config_from_file(config_file) || {} of String => String

  # Check if configured
  if config["GENTILITY_TOKEN"]?
    puts "✅ Configuration: Found"
    puts "   Config file: #{config_file}"
  else
    puts "❌ Configuration: Not found"
    puts "   Expected: #{config_file}"
    puts "   Run: sudo gentility auth"
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
  puts "    gentility [--debug] <COMMAND> [OPTIONS]"
  puts ""
  puts "COMMANDS:"
  puts "    auth                 Authenticate and provision machine key (required first step)"
  puts "    run, start           Start the agent daemon"
  puts "    status               Show agent configuration and service status"
  puts "    generate             Generate a new Ed25519 keypair (advanced)"
  puts "    setup <token>        Initial setup with machine key (advanced)"
  puts "    security <mode>      Configure security settings"
  puts "    test-totp <code>     Test TOTP validation"
  puts "    promiscuous <action> Configure promiscuous mode"
  puts "    version, -v, --version  Show version information"
  puts "    help, -h, --help     Show this help message"
  puts ""
  puts "GLOBAL OPTIONS:"
  puts "    --debug              Enable verbose debug logging (works with any command)"
  puts ""
  puts "AUTH OPTIONS:"
  puts "    -e, --env <env>          OAuth environment: prod (default) or dev"
  puts "    --headless               Don't auto-open browser (display URL only)"
  puts "    --org <id>               Organization ID (skip interactive prompt)"
  puts "    --environment <name>     Environment name (skip interactive prompt)"
  puts "    --nickname <name>        Agent nickname (skip interactive prompt)"
  puts ""
  puts "RUN OPTIONS:"
  puts "    --token=<token>      Access token (required for run command)"
  puts "    -e, --env <env>      Environment: prod (default) or dev"
  puts ""
  puts "SECURITY MODES:"
  puts "    totp [secret]        Enable TOTP authentication"
  puts "    password [pass]      Enable password authentication"
  puts "    none                 Disable security"
  puts "    clear-lockout        Clear rate limiting lockout state"
  puts ""
  puts "PROMISCUOUS ACTIONS:"
  puts "    enable               Enable promiscuous mode"
  puts "    disable              Disable promiscuous mode"
  puts "    status               Show promiscuous status"
  puts "    auth <password|totp> Set auth mode for promiscuous operations"
  puts ""
  puts "EXAMPLES:"
  puts "    # Step 1: Authenticate (required - provisions machine key)"
  puts "    gentility auth"
  puts "    gentility auth -e dev                    # For development OAuth server"
  puts "    gentility auth --headless                # Server/headless mode (shows URL)"
  puts "    gentility --debug auth                   # Debug mode for troubleshooting"
  puts "    "
  puts "    # Non-interactive authentication (for automation)"
  puts "    gentility auth --org <org-id> --environment production --nickname web-1"
  puts "    "
  puts "    # Step 2: Run agent"
  puts "    gentility run"
  puts "    gentility run -e dev --debug             # Development with debug logging"
  puts "    gentility auth --debug -e dev            # Debug can go anywhere in command"
  puts "    "
  puts "    # Configure security (optional)"
  puts "    gentility security totp"
  puts "    gentility security password mypass"
  puts "    "
  puts "    # Check status"
  puts "    gentility status"
  puts "    gentility version"
  puts "    "
  puts "    # Advanced: Manual keypair setup"
  puts "    gentility generate"
  puts "    gentility setup <generated_private_key>"
  puts ""
  puts "CONFIGURATION:"
  puts "    Config file: #{AgentConfig.get_config_path}"
  puts "    Service: sudo systemctl start gentility"
  puts ""
end

def main
  # Parse global --debug flag first (works with any command)
  CLI.debug_mode = ARGV.includes?("--debug")
  ARGV.delete("--debug")

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
      puts "the configuration file at #{AgentConfig.get_config_path}"
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

  # Check for auth command
  if ARGV[0] == "auth"
    environment = "prod"
    headless = false
    org_id = nil
    env_name = nil
    nickname = nil

    # Parse auth options
    i = 1
    while i < ARGV.size
      case ARGV[i]
      when "-e", "--env"
        if i + 1 < ARGV.size
          environment = ARGV[i + 1]
          i += 2
        else
          puts "Error: -e/--env requires an argument"
          exit 1
        end
      when "--headless"
        headless = true
        i += 1
      when "--org"
        if i + 1 < ARGV.size
          org_id = ARGV[i + 1]
          i += 2
        else
          puts "Error: --org requires an argument"
          exit 1
        end
      when "--environment"
        if i + 1 < ARGV.size
          env_name = ARGV[i + 1]
          i += 2
        else
          puts "Error: --environment requires an argument"
          exit 1
        end
      when "--nickname"
        if i + 1 < ARGV.size
          nickname = ARGV[i + 1]
          i += 2
        else
          puts "Error: --nickname requires an argument"
          exit 1
        end
      else
        puts "Unknown option: #{ARGV[i]}"
        puts "Usage: gentility auth [-e <env>] [--headless] [--debug] [--org <id>] [--environment <name>] [--nickname <name>]"
        exit 1
      end
    end

    # Check write permissions BEFORE starting OAuth flow
    config_file = AgentConfig.get_config_path
    config_dir = File.dirname(config_file)

    if File.exists?(config_file)
      unless File::Info.writable?(config_file)
        puts "❌ Permission denied: Cannot write to #{config_file}"
        puts ""
        puts "Please run with elevated privileges:"
        puts "  sudo gentility auth"
        exit 1
      end
    else
      unless File::Info.writable?(config_dir)
        puts "❌ Permission denied: Cannot write to directory #{config_dir}"
        puts ""
        puts "Please run with elevated privileges:"
        puts "  sudo gentility auth"
        exit 1
      end
    end

    run_oauth_flow(environment, headless, CLI.debug_mode, org_id, env_name, nickname)
    exit 0
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
        if mode == "clear-lockout"
          clear_lockout_from_cli
        else
          value = ARGV.size >= 3 ? ARGV[2] : nil
          setup_security(mode, value)
        end
      else
        puts "Usage: #{PROGRAM_NAME} security <mode> [value]"
        puts ""
        puts "Security modes:"
        puts "  totp [secret]       - Enable TOTP authentication (generates secret if not provided)"
        puts "  password [pass]     - Enable password authentication (prompts if not provided)"
        puts "  none                - Disable security"
        puts "  clear-lockout       - Clear rate limiting lockout state"
        puts ""
        puts "Examples:"
        puts "  #{PROGRAM_NAME} security totp"
        puts "  #{PROGRAM_NAME} security password mySecretPass123"
        puts "  #{PROGRAM_NAME} security none"
        puts "  #{PROGRAM_NAME} security clear-lockout"
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

  access_key, server_url, nickname, environment = parse_arguments

  agent = GentilityAgent.new(access_key, server_url, nickname, environment)

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

  Signal::HUP.trap do
    puts ""
    puts "Received SIGHUP, reloading security configuration..."
    agent.reload_security_config
  end

  agent.start
end
