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

  # Walk a nested path in a parsed YAML config, returning the value at the
  # leaf or nil if any intermediate key is missing or not a hash.
  def self.yaml_dig(config : YAML::Any?, *keys : String) : YAML::Any?
    current = config
    keys.each do |key|
      return nil unless c = current
      h = c.as_h?
      return nil unless h
      current = h[YAML::Any.new(key)]?
    end
    current
  end

  # Set a nested YAML value at `path`, creating intermediate hashes as needed.
  # Reads the existing file (or starts empty), mutates, writes back.
  def self.update_yaml(config_file : String, path : Array(String), value : String | Bool) : Nil
    raise ArgumentError.new("path must not be empty") if path.empty?

    root = load_root_hash(config_file)

    current = root
    path[0..-2].each do |key|
      key_any = YAML::Any.new(key)
      nested = current[key_any]?.try(&.as_h?)
      unless nested
        nested = {} of YAML::Any => YAML::Any
        current[key_any] = YAML::Any.new(nested)
      end
      current = nested
    end

    leaf_key = YAML::Any.new(path.last)
    current[leaf_key] = case value
                        in String then YAML::Any.new(value)
                        in Bool   then YAML::Any.new(value)
                        end

    File.write(config_file, root.to_yaml)
    File.chmod(config_file, 0o640)
  end

  # Delete a nested YAML value at `path`. No-op if the path doesn't exist.
  def self.delete_yaml(config_file : String, path : Array(String)) : Nil
    return unless File.exists?(config_file)
    raise ArgumentError.new("path must not be empty") if path.empty?

    root = load_root_hash(config_file)

    current = root
    path[0..-2].each do |key|
      nested = current[YAML::Any.new(key)]?.try(&.as_h?)
      return unless nested
      current = nested
    end

    current.delete(YAML::Any.new(path.last))

    File.write(config_file, root.to_yaml)
    File.chmod(config_file, 0o640)
  end

  private def self.load_root_hash(config_file : String) : Hash(YAML::Any, YAML::Any)
    return {} of YAML::Any => YAML::Any unless File.exists?(config_file)

    content = File.read(config_file)
    return {} of YAML::Any => YAML::Any if content.strip.empty?

    YAML.parse(content).as_h? || {} of YAML::Any => YAML::Any
  end
end
