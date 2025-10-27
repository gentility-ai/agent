require "./spec_helper"

describe "Config Loading" do
  describe "AgentConfig.load_config_from_file" do
    it "returns nil for non-existent file" do
      AgentConfig.load_config_from_file("/nonexistent/file.yaml").should be_nil
    end

    it "parses valid YAML config file" do
      config_content = <<-CONFIG
      # Test config
      access_key: test123
      server_url: wss://example.com
      nickname: test-agent
      debug: true
      CONFIG

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      config.should_not be_nil

      if config
        config["access_key"]?.try(&.as_s).should eq "test123"
        config["server_url"]?.try(&.as_s).should eq "wss://example.com"
        config["nickname"]?.try(&.as_s).should eq "test-agent"
        config["debug"]?.try(&.as_bool).should be_true
      end

      cleanup_test_file(temp_file)
    end

    it "parses YAML config with security section" do
      config_content = <<-CONFIG
      access_key: test_key
      security:
        mode: password
        password: testpass
        unlock_timeout: 1800
        extendable: true
      CONFIG

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      config.should_not be_nil

      if config
        config["access_key"]?.try(&.as_s).should eq "test_key"
        security = config["security"]?
        security.should_not be_nil

        if security
          security["mode"]?.try(&.as_s).should eq "password"
          security["password"]?.try(&.as_s).should eq "testpass"
          security["unlock_timeout"]?.try(&.as_i).should eq 1800
          security["extendable"]?.try(&.as_bool).should be_true
        end
      end

      cleanup_test_file(temp_file)
    end

    it "parses YAML config with encrypted_db_credentials" do
      config_content = <<-CONFIG
      access_key: test_key
      encrypted_db_credentials:
        db-12345: "base64encryptedcreds..."
        db-67890: "anotherencryptedvalue..."
      CONFIG

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      config.should_not be_nil

      if config
        creds = config["encrypted_db_credentials"]?
        creds.should_not be_nil

        if creds
          creds["db-12345"]?.try(&.as_s).should eq "base64encryptedcreds..."
          creds["db-67890"]?.try(&.as_s).should eq "anotherencryptedvalue..."
        end
      end

      cleanup_test_file(temp_file)
    end

    it "handles empty YAML config" do
      config_content = "{}"

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      config.should_not be_nil

      cleanup_test_file(temp_file)
    end

    it "handles comments in YAML" do
      config_content = <<-CONFIG
      # This is a comment
      access_key: test123
      # Another comment
      server_url: wss://example.com
      CONFIG

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      config.should_not be_nil

      if config
        config["access_key"]?.try(&.as_s).should eq "test123"
        config["server_url"]?.try(&.as_s).should eq "wss://example.com"
      end

      cleanup_test_file(temp_file)
    end

    it "handles invalid YAML gracefully" do
      config_content = "this is not: valid: yaml: content:"

      temp_file = "/tmp/gentility-test-#{Random.rand(100000)}.yaml"
      File.write(temp_file, config_content)

      config = AgentConfig.load_config_from_file(temp_file)
      # Should return nil on parse error
      config.should be_nil

      cleanup_test_file(temp_file)
    end
  end
end

describe "GentilityAgent" do
  describe "#initialize" do
    it "creates agent with valid Ed25519 key" do
      # Generate a valid key for testing
      signing_key = Ed25519::SigningKey.new
      access_key = Base58.encode(signing_key.key_bytes)

      agent = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test")
      agent.should_not be_nil
    end
  end
end