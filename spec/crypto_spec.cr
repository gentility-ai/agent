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

  describe "X25519 Key Exchange" do
    describe ".ed25519_seed_to_x25519_keypair" do
      it "converts Ed25519 seed to X25519 keypair" do
        # Generate a 32-byte seed
        seed = Random::Secure.random_bytes(32)

        # Convert to X25519
        private_key, public_key = AgentCrypto.ed25519_seed_to_x25519_keypair(seed)

        # Verify sizes
        private_key.size.should eq 32
        public_key.size.should eq 32
      end

      it "produces consistent keypairs from same seed" do
        seed = Random::Secure.random_bytes(32)

        private1, public1 = AgentCrypto.ed25519_seed_to_x25519_keypair(seed)
        private2, public2 = AgentCrypto.ed25519_seed_to_x25519_keypair(seed)

        private1.should eq private2
        public1.should eq public2
      end

      it "produces different keypairs from different seeds" do
        seed1 = Random::Secure.random_bytes(32)
        seed2 = Random::Secure.random_bytes(32)

        private1, public1 = AgentCrypto.ed25519_seed_to_x25519_keypair(seed1)
        private2, public2 = AgentCrypto.ed25519_seed_to_x25519_keypair(seed2)

        private1.should_not eq private2
        public1.should_not eq public2
      end

      it "raises error for invalid seed length" do
        invalid_seed = Random::Secure.random_bytes(16)

        expect_raises(Exception, /32 bytes/) do
          AgentCrypto.ed25519_seed_to_x25519_keypair(invalid_seed)
        end
      end
    end

    describe ".x25519_ecdh" do
      it "derives shared secret from two keypairs" do
        # Generate two keypairs
        seed_alice = Random::Secure.random_bytes(32)
        seed_bob = Random::Secure.random_bytes(32)

        alice_private, alice_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_alice)
        bob_private, bob_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_bob)

        # Derive shared secrets
        shared_secret_alice = AgentCrypto.x25519_ecdh(alice_private, bob_public)
        shared_secret_bob = AgentCrypto.x25519_ecdh(bob_private, alice_public)

        # Both parties should derive the same shared secret
        shared_secret_alice.should eq shared_secret_bob
        shared_secret_alice.size.should eq 32
      end

      it "produces consistent shared secrets" do
        seed_alice = Random::Secure.random_bytes(32)
        seed_bob = Random::Secure.random_bytes(32)

        alice_private, alice_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_alice)
        bob_private, bob_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_bob)

        # Derive multiple times
        shared1 = AgentCrypto.x25519_ecdh(alice_private, bob_public)
        shared2 = AgentCrypto.x25519_ecdh(alice_private, bob_public)

        shared1.should eq shared2
      end

      it "produces different shared secrets for different keypairs" do
        seed_alice = Random::Secure.random_bytes(32)
        seed_bob1 = Random::Secure.random_bytes(32)
        seed_bob2 = Random::Secure.random_bytes(32)

        alice_private, alice_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_alice)
        bob1_private, bob1_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_bob1)
        bob2_private, bob2_public = AgentCrypto.ed25519_seed_to_x25519_keypair(seed_bob2)

        shared1 = AgentCrypto.x25519_ecdh(alice_private, bob1_public)
        shared2 = AgentCrypto.x25519_ecdh(alice_private, bob2_public)

        shared1.should_not eq shared2
      end

      it "raises error for invalid private key length" do
        invalid_private = Random::Secure.random_bytes(16)
        valid_public = Random::Secure.random_bytes(32)

        expect_raises(Exception, /32 bytes/) do
          AgentCrypto.x25519_ecdh(invalid_private, valid_public)
        end
      end

      it "raises error for invalid public key length" do
        valid_private = Random::Secure.random_bytes(32)
        invalid_public = Random::Secure.random_bytes(16)

        expect_raises(Exception, /32 bytes/) do
          AgentCrypto.x25519_ecdh(valid_private, invalid_public)
        end
      end
    end

    describe ".decrypt_with_shared_secret" do
      it "decrypts AES-256-CBC encrypted data" do
        # Simulate server encrypting credentials
        shared_secret = Random::Secure.random_bytes(32)
        plaintext = %({
          "host": "db.example.com",
          "port": 5432,
          "database": "mydb",
          "username": "user",
          "password": "secret"
        })

        # Encrypt with OpenSSL (simulating server-side)
        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.encrypt
        cipher.key = shared_secret
        iv = Random::Secure.random_bytes(16)
        cipher.iv = iv

        # Get ciphertext
        io = IO::Memory.new
        io.write(cipher.update(plaintext))
        io.write(cipher.final)
        ciphertext = io.to_slice

        # Prepend IV to ciphertext
        payload = IO::Memory.new
        payload.write(iv)
        payload.write(ciphertext)

        # Encode for transmission (IV + ciphertext)
        encrypted_payload = Base64.strict_encode(payload.to_slice)

        # Decrypt using agent method
        decrypted = AgentCrypto.decrypt_with_shared_secret(
          shared_secret,
          encrypted_payload
        )

        decrypted.should eq plaintext
      end

      it "handles empty credentials" do
        shared_secret = Random::Secure.random_bytes(32)
        plaintext = ""

        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.encrypt
        cipher.key = shared_secret
        iv = Random::Secure.random_bytes(16)
        cipher.iv = iv

        io = IO::Memory.new
        io.write(cipher.update(plaintext))
        io.write(cipher.final)
        ciphertext = io.to_slice

        # Prepend IV to ciphertext
        payload = IO::Memory.new
        payload.write(iv)
        payload.write(ciphertext)

        encrypted_payload = Base64.strict_encode(payload.to_slice)

        decrypted = AgentCrypto.decrypt_with_shared_secret(
          shared_secret,
          encrypted_payload
        )

        decrypted.should eq plaintext
      end

      it "raises error for invalid shared secret length" do
        invalid_secret = Random::Secure.random_bytes(16)
        encrypted = Base64.strict_encode(Random::Secure.random_bytes(32))

        expect_raises(Exception, /32 bytes/) do
          AgentCrypto.decrypt_with_shared_secret(invalid_secret, encrypted)
        end
      end

      it "raises error for payload smaller than IV size" do
        secret = Random::Secure.random_bytes(32)
        # Payload must be at least 16 bytes (IV size)
        too_small = Base64.strict_encode(Random::Secure.random_bytes(8))

        expect_raises(Exception, /16 bytes/) do
          AgentCrypto.decrypt_with_shared_secret(secret, too_small)
        end
      end
    end

    describe "End-to-End X25519 Flow" do
      it "simulates complete agent-server credential exchange" do
        # Step 1: Agent generates X25519 keypair from ed25519 seed
        agent_seed = Random::Secure.random_bytes(32)
        agent_x25519_private, agent_x25519_public = AgentCrypto.ed25519_seed_to_x25519_keypair(agent_seed)

        # Step 2: Server generates X25519 keypair
        server_seed = Random::Secure.random_bytes(32)
        server_x25519_private, server_x25519_public = AgentCrypto.ed25519_seed_to_x25519_keypair(server_seed)

        # Step 3: Both parties derive shared secret
        agent_shared_secret = AgentCrypto.x25519_ecdh(agent_x25519_private, server_x25519_public)
        server_shared_secret = AgentCrypto.x25519_ecdh(server_x25519_private, agent_x25519_public)

        # Verify shared secrets match
        agent_shared_secret.should eq server_shared_secret

        # Step 4: Server encrypts credentials
        credentials = %({
          "host": "production-db.example.com",
          "port": 5432,
          "database": "app_production",
          "username": "app_user",
          "password": "super_secret_password_123!"
        })

        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.encrypt
        cipher.key = server_shared_secret
        iv = Random::Secure.random_bytes(16)
        cipher.iv = iv

        # Encrypt credentials
        ciphertext_io = IO::Memory.new
        ciphertext_io.write(cipher.update(credentials))
        ciphertext_io.write(cipher.final)
        ciphertext = ciphertext_io.to_slice

        # Prepend IV to ciphertext
        payload = IO::Memory.new
        payload.write(iv)
        payload.write(ciphertext)

        encrypted_payload = Base64.strict_encode(payload.to_slice)

        # Step 5: Agent decrypts credentials
        decrypted_credentials = AgentCrypto.decrypt_with_shared_secret(
          agent_shared_secret,
          encrypted_payload
        )

        # Verify decrypted credentials match original
        decrypted_credentials.should eq credentials

        # Verify we can parse the JSON
        parsed = JSON.parse(decrypted_credentials)
        parsed["host"].as_s.should eq "production-db.example.com"
        parsed["password"].as_s.should eq "super_secret_password_123!"
      end
    end
  end
end
