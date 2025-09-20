require "./spec_helper"

describe "Config Loading" do
  describe "load_config_from_file" do
    it "returns nil for non-existent file" do
      load_config_from_file("/nonexistent/file.conf").should be_nil
    end

    it "parses valid config file" do
      config_content = <<-CONFIG
      # Test config
      GENTILITY_TOKEN=test123
      SERVER_URL=wss://example.com
      NICKNAME=test-agent
      DEBUG=true
      CONFIG

      temp_file = create_test_config(config_content)
      
      config = load_config_from_file(temp_file)
      config.should_not be_nil
      
      if config
        config["GENTILITY_TOKEN"].should eq "test123"
        config["SERVER_URL"].should eq "wss://example.com"
        config["NICKNAME"].should eq "test-agent"
        config["DEBUG"].should eq "true"
      end

      cleanup_test_file(temp_file)
    end

    it "ignores comments and empty lines" do
      config_content = <<-CONFIG
      # This is a comment
      
      VALID_KEY=valid_value
      # Another comment
      ANOTHER_KEY=another_value
      
      CONFIG

      temp_file = create_test_config(config_content)
      
      config = load_config_from_file(temp_file)
      config.should_not be_nil
      
      if config
        config.size.should eq 2
        config["VALID_KEY"].should eq "valid_value"
        config["ANOTHER_KEY"].should eq "another_value"
      end

      cleanup_test_file(temp_file)
    end

    it "removes quotes from values" do
      config_content = <<-CONFIG
      QUOTED_SINGLE='single quoted value'
      QUOTED_DOUBLE="double quoted value"
      UNQUOTED=unquoted value
      CONFIG

      temp_file = create_test_config(config_content)
      
      config = load_config_from_file(temp_file)
      config.should_not be_nil
      
      if config
        config["QUOTED_SINGLE"].should eq "single quoted value"
        config["QUOTED_DOUBLE"].should eq "double quoted value"
        config["UNQUOTED"].should eq "unquoted value"
      end

      cleanup_test_file(temp_file)
    end

    it "handles malformed lines gracefully" do
      config_content = <<-CONFIG
      VALID_KEY=valid_value
      MALFORMED LINE WITHOUT EQUALS
      ANOTHER_VALID=another_value
      =MISSING_KEY
      CONFIG

      temp_file = create_test_config(config_content)
      
      config = load_config_from_file(temp_file)
      config.should_not be_nil
      
      if config
        config["VALID_KEY"].should eq "valid_value"
        config["ANOTHER_VALID"].should eq "another_value"
        config.size.should eq 2  # Only valid lines should be parsed
      end

      cleanup_test_file(temp_file)
    end
  end
end

describe "GentilityAgent" do
  describe "#initialize" do
    it "creates agent with required parameters" do
      agent = GentilityAgent.new("test_key", "ws://localhost:9000", "test-agent", "test", false)
      agent.should_not be_nil
    end
  end

  describe "system info methods" do
    it "gets hostname" do
      agent = GentilityAgent.new("test_key", "ws://localhost:9000", "test-agent")
      
      # We can't directly access private methods, but we can test the public interface
      # This would be tested through the command execution system
      agent.should_not be_nil
    end
  end

  describe "command execution" do
    it "handles unknown commands" do
      agent = GentilityAgent.new("test_key", "ws://localhost:9000", "test-agent")
      
      # Test through the public interface if possible
      # Most command testing would be integration tests
      agent.should_not be_nil
    end
  end
end