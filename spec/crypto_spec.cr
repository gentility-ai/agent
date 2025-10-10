require "./spec_helper"

describe AgentCrypto do
  describe ".parse_private_key" do
    it "parses a valid Ed25519 private key" do
      # Generate a test key
      signing_key = Ed25519::SigningKey.new
      base58_key = Base58.encode(signing_key.key_bytes)

      # Parse it back
      parsed_key = AgentCrypto.parse_private_key(base58_key)
      parsed_key.should_not be_nil
      parsed_key.key_bytes.size.should eq 32
    end

    it "raises error for invalid key length" do
      # Create an invalid key (wrong length)
      invalid_key = Base58.encode(Bytes.new(16))

      expect_raises(Ed25519::VerifyError) do
        AgentCrypto.parse_private_key(invalid_key)
      end
    end

    it "raises error for invalid base58" do
      expect_raises(Exception) do
        AgentCrypto.parse_private_key("not-valid-base58!!!")
      end
    end
  end

  describe ".public_key_base58" do
    it "derives public key from private key" do
      signing_key = Ed25519::SigningKey.new
      public_key = AgentCrypto.public_key_base58(signing_key)

      public_key.should_not be_nil
      public_key.size.should be > 0
    end

    it "produces consistent public keys" do
      signing_key = Ed25519::SigningKey.new
      public_key1 = AgentCrypto.public_key_base58(signing_key)
      public_key2 = AgentCrypto.public_key_base58(signing_key)

      public_key1.should eq public_key2
    end
  end

  describe ".derive_aes_key" do
    it "derives a 32-byte AES key" do
      signing_key = Ed25519::SigningKey.new
      aes_key = AgentCrypto.derive_aes_key(signing_key)

      aes_key.size.should eq 32
    end
  end

  describe ".encrypt and .decrypt" do
    it "encrypts and decrypts data correctly" do
      signing_key = Ed25519::SigningKey.new
      plaintext = "sensitive database credentials"

      encrypted = AgentCrypto.encrypt(signing_key, plaintext)
      encrypted.should_not be_nil
      encrypted.should_not eq plaintext

      decrypted = AgentCrypto.decrypt(signing_key, encrypted)
      decrypted.should eq plaintext
    end

    it "produces different ciphertext each time (due to IV)" do
      signing_key = Ed25519::SigningKey.new
      plaintext = "test data"

      encrypted1 = AgentCrypto.encrypt(signing_key, plaintext)
      encrypted2 = AgentCrypto.encrypt(signing_key, plaintext)

      encrypted1.should_not eq encrypted2

      # But both should decrypt to the same plaintext
      AgentCrypto.decrypt(signing_key, encrypted1).should eq plaintext
      AgentCrypto.decrypt(signing_key, encrypted2).should eq plaintext
    end

    it "handles empty strings" do
      signing_key = Ed25519::SigningKey.new
      plaintext = ""

      encrypted = AgentCrypto.encrypt(signing_key, plaintext)
      decrypted = AgentCrypto.decrypt(signing_key, encrypted)

      decrypted.should eq plaintext
    end

    it "handles large data" do
      signing_key = Ed25519::SigningKey.new
      plaintext = "x" * 10000

      encrypted = AgentCrypto.encrypt(signing_key, plaintext)
      decrypted = AgentCrypto.decrypt(signing_key, encrypted)

      decrypted.should eq plaintext
    end

    it "fails to decrypt with wrong key" do
      signing_key1 = Ed25519::SigningKey.new
      signing_key2 = Ed25519::SigningKey.new
      plaintext = "secret data"

      encrypted = AgentCrypto.encrypt(signing_key1, plaintext)

      expect_raises(Exception) do
        AgentCrypto.decrypt(signing_key2, encrypted)
      end
    end
  end

  describe ".store_credentials and .load_credentials" do
    it "stores and loads credentials from config file" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-credentials-#{Random.rand(100000)}.yaml"
      db_target_id = "db-12345"
      credentials = %({
        "host": "localhost",
        "port": 5432,
        "database": "testdb",
        "username": "testuser",
        "password": "testpass"
      })

      begin
        # Store credentials
        AgentCrypto.store_credentials(config_file, db_target_id, credentials, signing_key)

        # Verify file was created
        File.exists?(config_file).should be_true

        # Load credentials back
        loaded = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded.should_not be_nil
        loaded.should eq credentials

        # Verify it's a valid YAML file
        config = YAML.parse(File.read(config_file))
        config["encrypted_db_credentials"]?.should_not be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "stores multiple credentials in the same file" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-credentials-#{Random.rand(100000)}.yaml"
      db_target_id1 = "db-11111"
      db_target_id2 = "db-22222"
      credentials1 = %("host": "db1.example.com")
      credentials2 = %("host": "db2.example.com")

      begin
        # Store first set of credentials
        AgentCrypto.store_credentials(config_file, db_target_id1, credentials1, signing_key)

        # Store second set
        AgentCrypto.store_credentials(config_file, db_target_id2, credentials2, signing_key)

        # Load both back
        loaded1 = AgentCrypto.load_credentials(config_file, db_target_id1, signing_key)
        loaded2 = AgentCrypto.load_credentials(config_file, db_target_id2, signing_key)

        loaded1.should eq credentials1
        loaded2.should eq credentials2
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "returns nil for non-existent credentials" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-credentials-#{Random.rand(100000)}.yaml"

      begin
        # Create empty config
        File.write(config_file, "{}")

        loaded = AgentCrypto.load_credentials(config_file, "non-existent-id", signing_key)
        loaded.should be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "returns nil for non-existent config file" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/non-existent-#{Random.rand(100000)}.yaml"

      loaded = AgentCrypto.load_credentials(config_file, "any-id", signing_key)
      loaded.should be_nil
    end

    it "preserves existing config when storing credentials" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-credentials-#{Random.rand(100000)}.yaml"
      db_target_id = "db-12345"
      credentials = "test credentials"

      begin
        # Create config with some existing data
        existing_config = {
          "access_key" => "test_key_123",
          "server_url" => "wss://example.com",
        }
        File.write(config_file, existing_config.to_yaml)

        # Store credentials
        AgentCrypto.store_credentials(config_file, db_target_id, credentials, signing_key)

        # Verify existing config is preserved
        config = YAML.parse(File.read(config_file))
        config["access_key"]?.try(&.as_s).should eq "test_key_123"
        config["server_url"]?.try(&.as_s).should eq "wss://example.com"
        config["encrypted_db_credentials"]?.should_not be_nil
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end

    it "sets correct file permissions (600)" do
      signing_key = Ed25519::SigningKey.new
      config_file = "/tmp/test-credentials-#{Random.rand(100000)}.yaml"
      db_target_id = "db-12345"
      credentials = "test"

      begin
        AgentCrypto.store_credentials(config_file, db_target_id, credentials, signing_key)

        # Check file permissions
        stat = File.info(config_file)
        permissions = stat.permissions.value & 0o777
        permissions.should eq 0o600
      ensure
        File.delete(config_file) if File.exists?(config_file)
      end
    end
  end
end
