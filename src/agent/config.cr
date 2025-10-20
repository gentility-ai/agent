require "yaml"
require "file"

module AgentConfig
  # Environment-specific server URLs
  module ServerURLs
    # WebSocket server URLs (for agent connections)
    def self.websocket_url(environment : String) : String
      case environment
      when "dev", "development"
        "https://dev-ws.gentility.ai"
      else
        "https://ws.gentility.ai"
      end
    end

    # OAuth server URLs (for authentication)
    def self.oauth_authorize_url(environment : String) : String
      case environment
      when "dev", "development"
        "https://dev-mcp.gentility.ai/oauth/authorize"
      else
        "https://mcp.gentility.ai/oauth/authorize"
      end
    end

    def self.oauth_token_url(environment : String) : String
      case environment
      when "dev", "development"
        "https://dev-mcp.gentility.ai/oauth/token"
      else
        "https://mcp.gentility.ai/oauth/token"
      end
    end

    def self.oauth_device_code_url(environment : String) : String
      case environment
      when "dev", "development"
        "https://dev-mcp.gentility.ai/oauth/device/code"
      else
        "https://mcp.gentility.ai/oauth/device/code"
      end
    end
  end

  # Get the configuration file path
  def self.get_config_path : String
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

  # Load configuration from file
  def self.load_config_from_file(path : String) : YAML::Any?
    return nil unless File.exists?(path)

    YAML.parse(File.read(path))
  rescue ex : Exception
    puts "Error reading config file: #{ex.message}"
    nil
  end

  # Update a single config value
  def self.update_config(config_file : String, key : String, value : String)
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

  # Remove config keys
  def self.remove_config(config_file : String, keys : Array(String))
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
end
