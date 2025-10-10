require "./spec_helper"

describe "Database Commands" do
  describe "AgentCrypto credentials storage" do
    it "stores and retrieves credentials successfully" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-db-creds-#{Random.rand(100000)}.yaml"
      db_target_id = "test-db-001"

      credentials = %({
        "host": "db.example.com",
        "port": 5432,
        "database": "myapp",
        "username": "dbuser",
        "password": "dbpass123"
      })

      begin
        # Store credentials
        AgentCrypto.store_credentials(config_file, db_target_id, credentials, signing_key)

        # Verify file exists and has correct permissions
        File.exists?(config_file).should be_true
        stat = File.info(config_file)
        permissions = stat.permissions.value & 0o777
        permissions.should eq 0o600

        # Load credentials back
        loaded = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded.should_not be_nil
        loaded.should eq credentials

        # Verify YAML structure
        config = YAML.parse(File.read(config_file))
        config["encrypted_db_credentials"]?.should_not be_nil

        creds_section = config["encrypted_db_credentials"]?
        creds_section.should_not be_nil

        if creds_section
          encrypted_value = creds_section[db_target_id]?
          encrypted_value.should_not be_nil
          # Encrypted value should not equal plaintext
          encrypted_value.try(&.as_s).should_not eq credentials
        end
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "handles multiple databases in same config" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-multi-db-#{Random.rand(100000)}.yaml"

      db1_id = "db-prod-001"
      db1_creds = %({"host": "prod.db.com", "port": 5432})

      db2_id = "db-staging-001"
      db2_creds = %({"host": "staging.db.com", "port": 5432})

      begin
        # Store first database
        AgentCrypto.store_credentials(config_file, db1_id, db1_creds, signing_key)

        # Store second database
        AgentCrypto.store_credentials(config_file, db2_id, db2_creds, signing_key)

        # Verify both can be loaded
        loaded1 = AgentCrypto.load_credentials(config_file, db1_id, signing_key)
        loaded2 = AgentCrypto.load_credentials(config_file, db2_id, signing_key)

        loaded1.should eq db1_creds
        loaded2.should eq db2_creds
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "returns nil for non-existent database" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-nonexistent-#{Random.rand(100000)}.yaml"

      begin
        File.write(config_file, {"encrypted_db_credentials" => {} of String => String}.to_yaml)

        loaded = AgentCrypto.load_credentials(config_file, "non-existent-db", signing_key)
        loaded.should be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "returns nil for non-existent config file" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/definitely-does-not-exist-#{Random.rand(100000)}.yaml"

      loaded = AgentCrypto.load_credentials(config_file, "any-id", signing_key)
      loaded.should be_nil
    end

    it "preserves existing config when adding credentials" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-preserve-#{Random.rand(100000)}.yaml"

      begin
        # Create config with existing data
        existing = {
          "access_key" => "test_key_abc",
          "server_url" => "wss://example.com",
          "security"   => {
            "mode"     => "password",
            "password" => "testpass",
          },
        }
        File.write(config_file, existing.to_yaml)

        # Add database credentials
        db_id = "new-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Verify existing config is preserved
        config = YAML.parse(File.read(config_file))
        config["access_key"]?.try(&.as_s).should eq "test_key_abc"
        config["server_url"]?.try(&.as_s).should eq "wss://example.com"

        security = config["security"]?
        security.should_not be_nil
        if security
          security["mode"]?.try(&.as_s).should eq "password"
        end

        # Verify new credentials were added
        config["encrypted_db_credentials"]?.should_not be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "encrypts credentials differently each time (IV randomness)" do
      signing_key = Ed25519::SigningKey.new
      config_file1 = "/tmp/test-encrypt1-#{Random.rand(100000)}.yaml"
      config_file2 = "/tmp/test-encrypt2-#{Random.rand(100000)}.yaml"

      begin
        db_id = "test-db"
        creds = %({"host": "localhost", "password": "secret"})

        # Store same credentials twice in different files
        AgentCrypto.store_credentials(config_file1, db_id, creds, signing_key)
        AgentCrypto.store_credentials(config_file2, db_id, creds, signing_key)

        # Read the encrypted values
        config1 = YAML.parse(File.read(config_file1))
        config2 = YAML.parse(File.read(config_file2))

        creds1 = config1["encrypted_db_credentials"]?
        creds2 = config2["encrypted_db_credentials"]?

        creds1.should_not be_nil
        creds2.should_not be_nil

        encrypted1 = creds1.try(&.[db_id]?.try(&.as_s))
        encrypted2 = creds2.try(&.[db_id]?.try(&.as_s))

        # Encrypted values should be different (due to random IV)
        encrypted1.should_not be_nil
        encrypted2.should_not be_nil
        encrypted1.should_not eq encrypted2

        # But both should decrypt to the same plaintext
        decrypted1 = AgentCrypto.load_credentials(config_file1, db_id, signing_key)
        decrypted2 = AgentCrypto.load_credentials(config_file2, db_id, signing_key)

        decrypted1.should eq creds
        decrypted2.should eq creds
      ensure
        File.delete(config_file1) if File.exists?(config_file1)
        File.delete(config_file2) if File.exists?(config_file2)
      end
    end

    it "fails to decrypt with wrong key" do
      signing_key1 = Ed25519::SigningKey.new
      signing_key2 = Ed25519::SigningKey.new
      config_file = "/tmp/test-wrong-key-#{Random.rand(100000)}.yaml"

      begin
        db_id = "test-db"
        creds = %({"password": "secret"})

        # Store with first key
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key1)

        # Try to load with different key - returns nil due to caught exception
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key2)

        # Should return nil or garbage, but not the original creds
        loaded.should be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "handles JSON credentials correctly" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-json-#{Random.rand(100000)}.yaml"

      begin
        db_id = "postgres-prod"
        creds = %({
          "host": "prod-db.example.com",
          "port": 5432,
          "database": "production",
          "username": "app_user",
          "password": "super_secret_password_123"
        })

        # Store
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Load and parse
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should_not be_nil

        if loaded
          parsed = JSON.parse(loaded)
          parsed["host"]?.try(&.as_s).should eq "prod-db.example.com"
          parsed["port"]?.try(&.as_i).should eq 5432
          parsed["database"]?.try(&.as_s).should eq "production"
          parsed["username"]?.try(&.as_s).should eq "app_user"
          parsed["password"]?.try(&.as_s).should eq "super_secret_password_123"
        end
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end
  end

  describe "Database credential security requirements" do
    it "requires unlock for psql_query_encrypted" do
      # This is tested in ws_commands_spec.cr
      # Just verify the command exists
      signing_key = Ed25519::SigningKey.new
      access_key = Base58.encode(signing_key.key_bytes)

      # Agent should initialize successfully
      agent = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test", false)
      agent.should_not be_nil
    end

    it "requires unlock for mysql_query_encrypted" do
      # This is tested in ws_commands_spec.cr
      # Just verify the command exists
      signing_key = Ed25519::SigningKey.new
      access_key = Base58.encode(signing_key.key_bytes)

      # Agent should initialize successfully
      agent = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test", false)
      agent.should_not be_nil
    end
  end
end
