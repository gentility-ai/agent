require "spec"
require "json"
require "file"

# Set environment variable to prevent main from running
ENV["CRYSTAL_SPEC"] = "true"

require "../src/agent"

# Test configuration and utilities
module TestHelpers
  # Create a temporary config file for testing
  def create_test_config(content : String) : String
    temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.conf"
    File.write(temp_file, content)
    temp_file
  end

  # Clean up temporary files
  def cleanup_test_file(path : String)
    File.delete(path) if File.exists?(path)
  end

  # Mock WebSocket for testing
  class MockWebSocket
    getter messages_sent : Array(String)
    property closed : Bool

    def initialize
      @messages_sent = [] of String
      @closed = false
    end

    def send(data : String)
      @messages_sent << data
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  # Test data generators
  def generate_test_totp_secret
    "JBSWY3DPEHPK3PXP"
  end

  def generate_valid_totp_code(secret : String)
    totp = CrOTP::TOTP.new(secret)
    totp.generate
  end

  # WebSocket command test helpers
  def create_test_agent(security_mode = "none", password = nil, totp_secret = nil)
    signing_key = Ed25519::SigningKey.new
    access_key = Base58.encode(signing_key.key_bytes)
    config_file = "/tmp/test-ws-#{Random.rand(100000)}.yaml"

    # Build config content as YAML string to avoid type issues
    config_content = "access_key: #{access_key}\n"

    if security_mode != "none"
      config_content += "security:\n"
      config_content += "  mode: #{security_mode}\n"

      if password
        config_content += "  password: #{password}\n"
      end

      if totp_secret
        config_content += "  totp_secret: #{totp_secret}\n"
      end
    end

    File.write(config_file, config_content)
    ENV["GENTILITY_CONFIG"] = config_file

    agent = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test")
    {agent, config_file, signing_key}
  end

  def cleanup_test_agent(config_file)
    File.delete(config_file) if File.exists?(config_file)
    ENV.delete("GENTILITY_CONFIG")
    Security.configure("none", nil, nil, 1800, true)
  end
end

# Include helpers in spec context
include TestHelpers