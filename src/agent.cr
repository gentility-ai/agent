# MIT License
#
# Copyright (c) 2025 James Tippett & Gentility AI
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

# ALWAYS UPDATE THIS VERSION IF YOU CHANGE THIS FILE
VERSION = "1.0.18"

class GentilityAgent
  @websocket : HTTP::WebSocket?
  @access_key : String
  @server_url : String
  @nickname : String
  @environment : String
  @running : Bool = false
  @ping_fiber : Fiber?
  @debug : Bool = false

  def initialize(@access_key : String, @server_url : String, @nickname : String, @environment : String = "prod", @debug : Bool = false)
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
    max_retries = -1 # Infinite retries

    while @running
      begin
        connect
        retry_count = 0 # Reset retry count on successful connection

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
            puts "Waiting 5 seconds before reconnection attempt..."
            sleep 5.seconds
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
      scheme: uri.scheme == "https" ? "wss" : "ws",
      host: uri.host,
      port: uri.port,
      path: "/agent/ws/websocket",
      query: URI::Params.build do |params|
        params.add "access_key", @access_key
        params.add "version", VERSION
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
      # Respond to ping
      send_message({"type" => "pong", "timestamp" => Time.utc.to_unix_f})
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
      host = params.try(&.["host"]?.try(&.to_s))
      port = params.try(&.["port"]?.try(&.as_i?))
      dbname = params.try(&.["dbname"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if host && port && dbname && query
        execute_psql_query(host, port, dbname, query)
      else
        {"error" => "Missing required parameters: host, port, dbname, query"}
      end
    when "mysql_query"
      host = params.try(&.["host"]?.try(&.to_s))
      port = params.try(&.["port"]?.try(&.as_i?))
      dbname = params.try(&.["dbname"]?.try(&.to_s))
      query = params.try(&.["query"]?.try(&.to_s))

      if host && port && dbname && query
        execute_mysql_query(host, port, dbname, query)
      else
        {"error" => "Missing required parameters: host, port, dbname, query"}
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
    available_capabilities = [] of String

    capabilities_list.each do |capability|
      if capability_name = capability.try(&.to_s)
        if command_available?(capability_name)
          available_capabilities << capability_name
        end
      end
    end

    {
      "available_capabilities" => available_capabilities,
      "total_checked"          => capabilities_list.size,
      "total_available"        => available_capabilities.size,
      "timestamp"              => Time.utc.to_unix_f,
    }
  rescue ex : Exception
    {"error" => "Failed to check capabilities: #{ex.message}"}
  end

  private def command_available?(command : String) : Bool
    # Use 'which' to check if command is available
    result = `which #{command} 2>/dev/null`.strip
    !result.empty?
  rescue
    false
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

  private def execute_psql_query(host : String, port : Int32, dbname : String, query : String)
    puts "Executing PostgreSQL query on #{host}:#{port}/#{dbname}"
    puts "Query: #{query}"

    begin
      # Use psql with environment variable to avoid password prompt
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")
      psql_cmd = "PGPASSWORD='' psql -h #{host} -p #{port} -d #{dbname} -t -A -c \"#{escaped_query}\""

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
    }

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
def load_config_from_file(path : String) : Hash(String, String)?
  return nil unless File.exists?(path)

  config = {} of String => String
  File.each_line(path) do |line|
    line = line.strip
    next if line.empty? || line.starts_with?("#")

    if match = line.match(/^(\w+)\s*=\s*(.+)$/)
      key = match[1]
      value = match[2].gsub(/^["']|["']$/, "") # Remove quotes
      config[key] = value
    end
  end

  config
rescue ex : Exception
  puts "Error reading config file: #{ex.message}"
  nil
end

def parse_arguments
  access_key = nil
  server_url = "ws://localhost:9000"
  nickname = `hostname`.strip
  environment = "prod"
  debug = false

  # Check for --token and --debug arguments
  ARGV.each_with_index do |arg, index|
    if arg.starts_with?("--token=")
      access_key = arg.split("=", 2)[1]
    elsif arg == "--debug"
      debug = true
    end
  end

  # If not found in arguments, check environment
  if access_key.nil?
    access_key = ENV["GENTILITY_TOKEN"]?
  end

  # Check for other arguments (for backward compatibility)
  non_token_args = ARGV.reject { |arg| arg.starts_with?("--token=") || arg == "--debug" }
  if non_token_args.size > 0 && access_key.nil?
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

  # Load configuration from file if it exists (can be overridden by args/env)
  config_file = "/etc/gentility.conf"
  config = load_config_from_file(config_file) || {} of String => String

  access_key = access_key || config["ACCESS_KEY"]? || config["GENTILITY_TOKEN"]?
  server_url = server_url == "ws://localhost:9000" ? (config["SERVER_URL"]? || server_url) : server_url
  nickname = nickname == `hostname`.strip ? (config["NICKNAME"]? || nickname) : nickname
  environment = environment == "prod" ? (config["ENVIRONMENT"]? || environment) : environment

  unless access_key
    puts "ERROR: No access token provided!"
    puts ""
    puts "Please provide your Gentility access token using one of these methods:"
    puts "  1. Command line: #{PROGRAM_NAME} --token=YOUR_TOKEN_HERE"
    puts "  2. Environment variable: export GENTILITY_TOKEN=YOUR_TOKEN_HERE"
    puts "  3. Config file: echo 'GENTILITY_TOKEN=YOUR_TOKEN_HERE' > #{config_file}"
    puts "  4. Legacy argument: #{PROGRAM_NAME} YOUR_TOKEN_HERE"
    puts ""
    puts "Optional arguments:"
    puts "  --token=TOKEN       Your server access token (required)"
    puts "  --debug             Enable debug logging for message traffic"
    puts "  SERVER_URL          Server URL (default: ws://localhost:9000)"
    puts "  NICKNAME            Agent nickname (default: hostname)"
    puts "  ENVIRONMENT         Environment: prod or staging (default: prod)"
    puts ""
    puts "Example: #{PROGRAM_NAME} --token=abc123xyz wss://my-server.com my-agent prod"
    exit 1
  end

  {access_key, server_url, nickname, environment, debug}
end

def main
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

main
