require "spec"
require "json"
require "file"
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
    getter messages_sent : Array(Bytes)
    property closed : Bool

    def initialize
      @messages_sent = [] of Bytes
      @closed = false
    end

    def send(data : Bytes)
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
end

# Include helpers in spec context
include TestHelpers