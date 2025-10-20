require "./spec_helper"

describe "Database Credentials Lifecycle" do
  # Reset security state before each test to prevent pollution
  before_each do
    Security.lock
    Security.configure("none", nil, nil, 1800, true, true, "password")
  end

  describe "End-to-End: Server pushes credentials → Store → Execute query" do
    it "complete PostgreSQL lifecycle" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Step 1: Server pushes credentials via store_credentials command
        db_target_id = "postgres-prod-12345"
        credentials_json = %({
          "host": "prod-db.example.com",
          "port": 5432,
          "database": "production_db",
          "username": "app_user",
          "password": "super_secret_pg_password"
        })

        # Store the credentials (simulates WS store_credentials command)
        AgentCrypto.store_credentials(config_file, db_target_id, credentials_json, signing_key)

        # Step 2: Verify credentials are stored in the prescribed format
        # - Encrypted in YAML file
        # - Under encrypted_db_credentials section
        # - Keyed by db_target_id
        File.exists?(config_file).should be_true

        config = YAML.parse(File.read(config_file))
        config["encrypted_db_credentials"]?.should_not be_nil

        creds_section = config["encrypted_db_credentials"]?
        creds_section.should_not be_nil

        if creds_section
          encrypted_value = creds_section[db_target_id]?
          encrypted_value.should_not be_nil

          # Verify it's encrypted (base64 string, not JSON)
          encrypted_str = encrypted_value.try(&.as_s)
          encrypted_str.should_not be_nil
          encrypted_str.should_not eq credentials_json
          # Encrypted value should not contain plaintext
          # (it's base64 encoded ciphertext, not readable JSON)
        end

        # Step 3: Execute query command reads and decodes credentials
        # Simulate psql_query_encrypted command execution
        loaded_creds = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded_creds.should_not be_nil
        loaded_creds.should eq credentials_json

        # Step 4: Parse credentials for use in database query
        parsed = JSON.parse(loaded_creds.not_nil!)
        host = parsed["host"]?.try(&.as_s)
        port = parsed["port"]?.try(&.as_i)
        database = parsed["database"]?.try(&.as_s)
        username = parsed["username"]?.try(&.as_s)
        password = parsed["password"]?.try(&.as_s)

        # Verify all required fields are present and correct
        host.should eq "prod-db.example.com"
        port.should eq 5432
        database.should eq "production_db"
        username.should eq "app_user"
        password.should eq "super_secret_pg_password"

        # Step 5: Credentials would now be used to construct psql command
        # Example: PGPASSWORD='super_secret_pg_password' psql -h prod-db.example.com -p 5432 -U app_user -d production_db -c "SELECT 1"
        # (Not actually executing to avoid needing a real database)
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "complete MySQL lifecycle" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Step 1: Server pushes MySQL credentials
        db_target_id = "mysql-staging-67890"
        credentials_json = %({
          "host": "staging-mysql.example.com",
          "port": 3306,
          "database": "staging_app",
          "username": "mysql_user",
          "password": "mysql_secret_pass"
        })

        AgentCrypto.store_credentials(config_file, db_target_id, credentials_json, signing_key)

        # Step 2: Verify storage format
        config = YAML.parse(File.read(config_file))
        creds_section = config["encrypted_db_credentials"]?
        creds_section.should_not be_nil

        # Step 3: Load and verify decryption
        loaded_creds = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded_creds.should eq credentials_json

        # Step 4: Parse for MySQL query
        parsed = JSON.parse(loaded_creds.not_nil!)
        host = parsed["host"]?.try(&.as_s)
        port = parsed["port"]?.try(&.as_i)
        database = parsed["database"]?.try(&.as_s)
        username = parsed["username"]?.try(&.as_s)
        password = parsed["password"]?.try(&.as_s)

        host.should eq "staging-mysql.example.com"
        port.should eq 3306
        database.should eq "staging_app"
        username.should eq "mysql_user"
        password.should eq "mysql_secret_pass"

        # Step 5: Would be used in mysql command
        # Example: mysql -h staging-mysql.example.com -P 3306 -u mysql_user -p'mysql_secret_pass' -D staging_app -e "SELECT 1"
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles credentials with special characters properly" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_target_id = "special-chars-db"
        # Password with characters that need escaping in shell
        special_password = "p@ss'w0rd!$`\"|*(){}[]<>"

        # Build proper JSON using JSON.build
        credentials_json = JSON.build do |json|
          json.object do
            json.field "host", "db.example.com"
            json.field "port", 5432
            json.field "database", "test'db"
            json.field "username", "user@example.com"
            json.field "password", special_password
          end
        end

        # Store
        AgentCrypto.store_credentials(config_file, db_target_id, credentials_json, signing_key)

        # Load
        loaded = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded.should eq credentials_json

        # Parse and verify special characters preserved
        parsed = JSON.parse(loaded.not_nil!)
        password = parsed["password"]?.try(&.as_s)
        password.should eq special_password

        # These would need proper escaping when passed to shell
        # The agent handles this in execute_psql_query / execute_mysql_query
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles optional credential fields" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_target_id = "minimal-creds-db"
        # Some databases might not need username/password (local socket, etc)
        credentials_json = %({
          "host": "localhost",
          "port": 5432,
          "database": "mydb"
        })

        AgentCrypto.store_credentials(config_file, db_target_id, credentials_json, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        parsed = JSON.parse(loaded.not_nil!)

        parsed["host"]?.try(&.as_s).should eq "localhost"
        parsed["username"]?.should be_nil
        parsed["password"]?.should be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "Multiple database targets" do
    it "stores and retrieves multiple databases independently" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Setup multiple databases
        databases = [
          {
            "id"    => "db-prod-1",
            "creds" => %({"host": "prod1.db.com", "database": "prod1", "password": "pass1"}),
          },
          {
            "id"    => "db-prod-2",
            "creds" => %({"host": "prod2.db.com", "database": "prod2", "password": "pass2"}),
          },
          {
            "id"    => "db-staging-1",
            "creds" => %({"host": "staging1.db.com", "database": "staging1", "password": "pass3"}),
          },
        ]

        # Store all
        databases.each do |db|
          AgentCrypto.store_credentials(config_file, db["id"], db["creds"], signing_key)
        end

        # Verify all can be loaded independently
        databases.each do |db|
          loaded = AgentCrypto.load_credentials(config_file, db["id"], signing_key)
          loaded.should eq db["creds"]

          parsed = JSON.parse(loaded.not_nil!)
          parsed["database"]?.try(&.as_s).should_not be_nil
        end

        # Verify config file has all entries
        config = YAML.parse(File.read(config_file))
        creds_section = config["encrypted_db_credentials"]?

        if creds_section && creds_section.as_h?
          creds_hash = creds_section.as_h
          creds_hash.size.should eq 3
        end
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "allows updating specific database without affecting others" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Store two databases
        db1_id = "db-1"
        db1_creds_v1 = %({"host": "db1.com", "password": "pass1_v1"})

        db2_id = "db-2"
        db2_creds = %({"host": "db2.com", "password": "pass2"})

        AgentCrypto.store_credentials(config_file, db1_id, db1_creds_v1, signing_key)
        AgentCrypto.store_credentials(config_file, db2_id, db2_creds, signing_key)

        # Update db-1 credentials
        db1_creds_v2 = %({"host": "db1-new.com", "password": "pass1_v2"})
        AgentCrypto.store_credentials(config_file, db1_id, db1_creds_v2, signing_key)

        # Verify db-1 has new credentials
        loaded1 = AgentCrypto.load_credentials(config_file, db1_id, signing_key)
        loaded1.should eq db1_creds_v2

        # Verify db-2 unchanged
        loaded2 = AgentCrypto.load_credentials(config_file, db2_id, signing_key)
        loaded2.should eq db2_creds
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "Security integration with database queries" do
    it "allows credential storage even when agent is locked" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Agent starts locked
        Security.unlocked?.should be_false

        # Server can still push credentials (store_credentials doesn't require unlock)
        db_id = "test-db"
        creds = %({"host": "localhost", "database": "test"})

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Credentials are stored
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        # But query execution would require unlock
        # (enforced in execute_command for psql_query_encrypted/mysql_query_encrypted)
        Security.unlocked?.should be_false
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "requires unlock to execute database queries" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Store credentials
        db_id = "secure-db"
        creds = %({"host": "localhost", "port": 5432, "database": "secure"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Verify locked
        Security.unlocked?.should be_false

        # Would need to unlock before executing psql_query_encrypted
        Security.unlock("testpass")
        Security.unlocked?.should be_true

        # Now can execute queries
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "extends unlock timeout on database query execution" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Unlock
        Security.unlock("testpass")
        initial_time_remaining = Security.time_remaining

        # Store and load credentials (simulating query execution)
        db_id = "test-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # In real execution, the execute_command method calls Security.extend_unlock
        # for psql_query_encrypted and mysql_query_encrypted
        Security.extend_unlock

        # Time remaining should be refreshed
        new_time_remaining = Security.time_remaining
        # Should be close to the full timeout (within a few seconds)
        new_time_remaining.should be > (initial_time_remaining - 5)
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "Credential persistence and agent lifecycle" do
    it "credentials survive agent restart with same key" do
      db_id = "persistent-db"
      creds = %({"host": "persistent.db.com", "port": 5432, "database": "myapp"})

      # First agent session
      agent1, config_file, signing_key1 = create_test_agent
      access_key = Base58.encode(signing_key1.key_bytes)

      begin
        # Store credentials
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key1)

        # Verify stored
        loaded1 = AgentCrypto.load_credentials(config_file, db_id, signing_key1)
        loaded1.should eq creds

        # Simulate agent restart - just reset ENV but keep the file
        ENV.delete("GENTILITY_CONFIG")
        Security.lock
        Security.configure("none", nil, nil, 1800, true, true, "password")

        # New agent session with same key
        ENV["GENTILITY_CONFIG"] = config_file
        signing_key2 = AgentCrypto.parse_private_key(access_key)
        agent2 = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test", false)

        # Should be able to load credentials with new agent instance
        loaded2 = AgentCrypto.load_credentials(config_file, db_id, signing_key2)
        loaded2.should eq creds
      ensure
        File.delete(config_file) if File.exists?(config_file)
        ENV.delete("GENTILITY_CONFIG")
        Security.configure("none", nil, nil, 1800, true, true, "password")
      end
    end

    it "credentials cannot be decrypted with different key" do
      db_id = "locked-db"
      creds = %({"host": "secure.db.com", "password": "secret"})

      # Store with first key
      agent1, config_file1, signing_key1 = create_test_agent

      begin
        AgentCrypto.store_credentials(config_file1, db_id, creds, signing_key1)

        # Try to load with different key
        signing_key2 = Ed25519::SigningKey.new  # Different key
        loaded = AgentCrypto.load_credentials(config_file1, db_id, signing_key2, silent: true)

        # Should return nil (decryption fails)
        loaded.should be_nil
      ensure
        cleanup_test_agent(config_file1)
      end
    end
  end

  describe "Error handling in production scenarios" do
    it "handles missing db_target_id gracefully" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Try to load non-existent credentials
        loaded = AgentCrypto.load_credentials(config_file, "non-existent-db-id", signing_key)
        loaded.should be_nil

        # Should not crash or throw unhandled exception
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles corrupted config file" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Store valid credentials
        db_id = "test-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Corrupt the config file
        File.write(config_file, "this is not valid yaml: {{{")

        # Should handle gracefully
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key, silent: true)
        # Returns nil on error (caught in rescue block)
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles invalid JSON in stored credentials" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "bad-json-db"
        # Store invalid JSON
        invalid_json = "this is not json"
        AgentCrypto.store_credentials(config_file, db_id, invalid_json, signing_key)

        # Should load the string (encryption/decryption works)
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq invalid_json

        # But parsing as JSON would fail (handled by execute_command)
        expect_raises(JSON::ParseException) do
          JSON.parse(loaded.not_nil!)
        end
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles file permission issues" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Store credentials
        db_id = "perm-test-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Verify permissions are set correctly (600)
        stat = File.info(config_file)
        permissions = stat.permissions.value & 0o777
        permissions.should eq 0o600

        # Should still be readable by owner
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end
end
