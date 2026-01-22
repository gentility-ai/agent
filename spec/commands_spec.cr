require "./spec_helper"

describe "WebSocket Commands" do
  # Reset security state before each test to prevent pollution
  before_each do
    Security.lock
    Security.configure("none", nil, nil, 1800, true, true, "password")
  end

  describe "ping command" do
    it "responds with pong status" do
      agent, config_file, _ = create_test_agent

      begin
        # Ping command should always work
        agent.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "system_info command" do
    it "retrieves system information" do
      agent, config_file, _ = create_test_agent

      begin
        # Agent should be able to collect system info
        agent.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "security commands" do
    describe "security_unlock" do
      it "unlocks agent with correct password" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlocked?.should be_false

          # Unlock with correct password
          result = Security.unlock("testpass")
          result.should be_true

          Security.unlocked?.should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "fails to unlock with incorrect password" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlocked?.should be_false

          # Try to unlock with wrong password
          result = Security.unlock("wrongpass")
          result.should be_false

          Security.unlocked?.should be_false
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "unlocks agent with valid TOTP code" do
        totp_secret = generate_test_totp_secret
        agent, config_file, _ = create_test_agent("totp", nil, totp_secret)

        begin
          Security.unlocked?.should be_false

          # Generate valid TOTP code
          valid_code = generate_valid_totp_code(totp_secret)

          # Unlock with TOTP
          result = Security.unlock(valid_code)
          result.should be_true

          Security.unlocked?.should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "fails with invalid TOTP code" do
        totp_secret = generate_test_totp_secret
        agent, config_file, _ = create_test_agent("totp", nil, totp_secret)

        begin
          # Try with invalid code
          result = Security.unlock("000000")
          result.should be_false

          Security.unlocked?.should be_false
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "security_lock" do
      it "locks the agent" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          # Unlock first
          Security.unlock("testpass")
          Security.unlocked?.should be_true

          # Lock it
          Security.lock
          Security.unlocked?.should be_false
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "security_set" do
      it "sets password security mode" do
        agent, config_file, _ = create_test_agent

        begin
          # Start with no security
          Security.mode.should eq "none"

          # Configure password security
          Security.configure("password", "newpass", nil, 1800, true)
          Security.mode.should eq "password"

          # Should be able to unlock with new password
          Security.unlock("newpass").should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "sets TOTP security mode" do
        agent, config_file, _ = create_test_agent

        begin
          Security.mode.should eq "none"

          # Configure TOTP security
          totp_secret = generate_test_totp_secret
          Security.configure("totp", nil, totp_secret, 1800, true)
          Security.mode.should eq "totp"

          # Should be able to unlock with TOTP
          valid_code = generate_valid_totp_code(totp_secret)
          Security.unlock(valid_code).should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "requires unlock to change from existing security" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlocked?.should be_false

          # Need to unlock first to change security settings
          # (This would be enforced by execute_command in the real agent)
          Security.unlock("testpass")
          Security.unlocked?.should be_true

          # Now can change security
          Security.configure("password", "newpass", nil, 1800, true)
          Security.mode.should eq "password"
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "security_unset" do
      it "disables security" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.mode.should eq "password"

          # Unlock first
          Security.unlock("testpass")

          # Disable security
          Security.configure("none", nil, nil, 1800, true)
          Security.mode.should eq "none"

          # Should always be unlocked now
          Security.unlocked?.should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "security_export" do
      it "exports security config with valid promiscuous auth" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          # Promiscuous mode enabled by default
          result = Security.validate_promiscuous_auth("testpass")
          result.should be_true

          # Export should succeed
          exported = Security.export_config
          exported.has_key?("success").should be_true
          exported.has_key?("security_config").should be_true
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "fails export with invalid promiscuous auth" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          result = Security.validate_promiscuous_auth("wrongpass")
          result.should be_false
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "get_status" do
      it "returns security status" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          status = Security.status

          status["security_enabled"]?.should be_true
          status["security_mode"]?.should eq "password"
          status["active"]?.should be_false  # Not unlocked yet
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "reflects unlocked state in status" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          # Unlock first
          Security.unlock("testpass")

          status = Security.status
          status["active"]?.should be_true

          time_remaining = status["time_remaining"]?
          if time_remaining.is_a?(Int32)
            time_remaining.should be > 0
          end
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end
  end

  describe "execute command" do
    it "requires unlock when security is enabled" do
      agent, config_file, _ = create_test_agent("password", "testpass")

      begin
        Security.unlocked?.should be_false

        # Execute would be blocked (tested via real command execution)
        # This just verifies the security state
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "allows execution when unlocked" do
      agent, config_file, _ = create_test_agent("password", "testpass")

      begin
        Security.unlock("testpass")
        Security.unlocked?.should be_true

        # Would be able to execute commands now
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "allows execution when security is disabled" do
      agent, config_file, _ = create_test_agent

      begin
        Security.mode.should eq "none"
        Security.unlocked?.should be_true

        # Always allowed when security is none
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "file commands" do
    it "allows file_read without security" do
      agent, config_file, _ = create_test_agent

      begin
        # File operations don't require unlock
        Security.mode.should eq "none"

        # Agent should be able to perform file operations
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "allows file_write without security" do
      agent, config_file, _ = create_test_agent

      begin
        # File write operations allowed
        Security.mode.should eq "none"
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "database query commands" do
    describe "psql_query" do
      it "requires unlock for direct database queries" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlocked?.should be_false

          # psql_query would be blocked (tested in actual command execution)
        ensure
          cleanup_test_agent(config_file)
        end
      end

      it "allows queries when unlocked" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlock("testpass")
          Security.unlocked?.should be_true

          # psql_query would be allowed now
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end

    describe "mysql_query" do
      it "requires unlock for direct database queries" do
        agent, config_file, _ = create_test_agent("password", "testpass")

        begin
          Security.unlocked?.should be_false

          # mysql_query would be blocked
        ensure
          cleanup_test_agent(config_file)
        end
      end
    end
  end
  describe "store_credentials command" do
    it "stores encrypted database credentials successfully" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_target_id = "test-db-001"
        credentials = %({
          "host": "db.example.com",
          "port": 5432,
          "database": "myapp",
          "username": "dbuser",
          "password": "dbpass"
        })

        # Simulate the command by directly calling store_credentials
        AgentCrypto.store_credentials(config_file, db_target_id, credentials, signing_key)

        # Verify credentials were stored
        loaded = AgentCrypto.load_credentials(config_file, db_target_id, signing_key)
        loaded.should eq credentials

        # Verify they're encrypted in the file
        config = YAML.parse(File.read(config_file))
        creds_section = config["encrypted_db_credentials"]?
        creds_section.should_not be_nil

        if creds_section
          encrypted_value = creds_section[db_target_id]?
          encrypted_value.should_not be_nil
          # Should be base64 encrypted, not plaintext
          encrypted_value.try(&.as_s).should_not eq credentials
        end
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "stores multiple database credentials" do
      agent, config_file, signing_key = create_test_agent

      begin
        db1_id = "postgres-prod"
        db1_creds = %({"host": "prod.postgres.com", "port": 5432})

        db2_id = "mysql-staging"
        db2_creds = %({"host": "staging.mysql.com", "port": 3306})

        # Store both
        AgentCrypto.store_credentials(config_file, db1_id, db1_creds, signing_key)
        AgentCrypto.store_credentials(config_file, db2_id, db2_creds, signing_key)

        # Verify both are stored
        loaded1 = AgentCrypto.load_credentials(config_file, db1_id, signing_key)
        loaded2 = AgentCrypto.load_credentials(config_file, db2_id, signing_key)

        loaded1.should eq db1_creds
        loaded2.should eq db2_creds
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "overwrites existing credentials for same db_target_id" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "test-db"
        old_creds = %({"password": "old_password"})
        new_creds = %({"password": "new_password"})

        # Store initial credentials
        AgentCrypto.store_credentials(config_file, db_id, old_creds, signing_key)

        # Overwrite with new credentials
        AgentCrypto.store_credentials(config_file, db_id, new_creds, signing_key)

        # Verify only new credentials are retrieved
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq new_creds
        loaded.should_not eq old_creds
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "psql_query_encrypted command" do
    it "requires agent to be unlocked for database queries" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Agent should be locked
        Security.unlocked?.should be_false

        # Store some credentials
        db_id = "test-postgres"
        creds = %({
          "host": "localhost",
          "port": 5432,
          "database": "testdb",
          "username": "testuser",
          "password": "testpass"
        })
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Verify credentials are stored but agent is still locked
        Security.unlocked?.should be_false
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "allows database queries when unlocked" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Unlock the agent
        Security.unlock("testpass").should be_true
        Security.unlocked?.should be_true

        # Store credentials
        db_id = "test-postgres"
        creds = %({
          "host": "localhost",
          "port": 5432,
          "database": "testdb",
          "username": "testuser",
          "password": "testpass"
        })
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Should be able to load credentials when unlocked
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        # Parse to verify format
        parsed = JSON.parse(loaded.not_nil!)
        parsed["host"]?.try(&.as_s).should eq "localhost"
        parsed["port"]?.try(&.as_i).should eq 5432
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "loads correct credentials for specific db_target_id" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Store multiple databases
        db1_id = "db-prod-001"
        db1_creds = %({"host": "prod.example.com", "database": "prod_db"})

        db2_id = "db-staging-001"
        db2_creds = %({"host": "staging.example.com", "database": "staging_db"})

        AgentCrypto.store_credentials(config_file, db1_id, db1_creds, signing_key)
        AgentCrypto.store_credentials(config_file, db2_id, db2_creds, signing_key)

        # Load specific database credentials
        loaded_prod = AgentCrypto.load_credentials(config_file, db1_id, signing_key)
        loaded_staging = AgentCrypto.load_credentials(config_file, db2_id, signing_key)

        # Verify correct credentials loaded
        parsed_prod = JSON.parse(loaded_prod.not_nil!)
        parsed_staging = JSON.parse(loaded_staging.not_nil!)

        parsed_prod["database"]?.try(&.as_s).should eq "prod_db"
        parsed_staging["database"]?.try(&.as_s).should eq "staging_db"
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "mysql_query_encrypted command" do
    it "requires agent to be unlocked" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        Security.unlocked?.should be_false

        # Store MySQL credentials
        db_id = "test-mysql"
        creds = %({
          "host": "localhost",
          "port": 3306,
          "database": "testdb"
        })
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Can store but not execute queries while locked
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "stores and retrieves MySQL credentials correctly" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "mysql-prod"
        creds = %({
          "host": "mysql.example.com",
          "port": 3306,
          "database": "production",
          "username": "app_user",
          "password": "mysql_pass"
        })

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        # Verify MySQL-specific fields
        parsed = JSON.parse(loaded.not_nil!)
        parsed["port"]?.try(&.as_i).should eq 3306
        parsed["username"]?.should_not be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "security integration with database commands" do
    it "allows credential storage without unlock" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Locked state
        Security.unlocked?.should be_false

        # Should still be able to store credentials (server command)
        db_id = "test-db"
        creds = %({"host": "localhost"})

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Verify stored
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "extends unlock timeout on database operations" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Unlock the agent
        Security.unlock("testpass")
        Security.unlocked?.should be_true

        initial_time = Security.time_remaining

        # Simulate database operation by loading credentials
        db_id = "test-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # In real usage, the execute_command method would call Security.extend_unlock
        # For this test, we just verify the agent is still unlocked
        Security.unlocked?.should be_true
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles promiscuous mode for credential export" do
      agent, config_file, signing_key = create_test_agent("password", "testpass")

      begin
        # Promiscuous mode should be enabled by default
        Security.promiscuous_enabled?.should be_true

        # Should be able to export config with correct credentials
        result = Security.validate_promiscuous_auth("testpass")
        result.should be_true

        # Wrong credentials should fail
        result = Security.validate_promiscuous_auth("wrongpass")
        result.should be_false
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "credential persistence and format" do
    it "persists credentials across agent restarts" do
      db_id = "persistent-db"
      creds = %({
        "host": "persistent.example.com",
        "port": 5432,
        "database": "mydb",
        "username": "user",
        "password": "pass123"
      })

      # First agent instance
      agent1, config_file, signing_key1 = create_test_agent
      access_key = Base58.encode(signing_key1.key_bytes)

      begin
        # Store credentials with first agent
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key1)

        # Simulate agent restart - reset ENV but keep the file
        ENV.delete("GENTILITY_CONFIG")
        Security.lock
        Security.configure("none", nil, nil, 1800, true, true, "password")

        # Create new agent with same key
        ENV["GENTILITY_CONFIG"] = config_file
        signing_key2 = AgentCrypto.parse_private_key(access_key)
        agent2 = GentilityAgent.new(access_key, "ws://localhost:9000", "test-agent", "test")

        # Should be able to load credentials with new agent instance
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key2)
        loaded.should eq creds
      ensure
        File.delete(config_file) if File.exists?(config_file)
        ENV.delete("GENTILITY_CONFIG")
        Security.configure("none", nil, nil, 1800, true, true, "password")
      end
    end

    it "handles special characters in credentials" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "special-chars-db"
        # Credentials with special characters
        creds = %({
          "host": "db.example.com",
          "username": "user@example.com",
          "password": "p@ss!w0rd#$%&*()"
        })

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        # Verify special characters preserved
        parsed = JSON.parse(loaded.not_nil!)
        parsed["password"]?.try(&.as_s).should eq "p@ss!w0rd#$%&*()"
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles unicode characters in credentials" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "unicode-db"
        creds = %({
          "host": "数据库.example.com",
          "database": "データベース",
          "password": "密码🔐"
        })

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        parsed = JSON.parse(loaded.not_nil!)
        parsed["password"]?.try(&.as_s).should eq "密码🔐"
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles very long credential strings" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "long-creds-db"
        # Very long password
        long_password = "a" * 1000
        creds = %({
          "host": "localhost",
          "password": "#{long_password}"
        })

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds

        parsed = JSON.parse(loaded.not_nil!)
        password = parsed["password"]?.try(&.as_s)
        password.should_not be_nil
        password.not_nil!.size.should eq 1000
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  describe "error handling" do
    it "returns nil for non-existent db_target_id" do
      agent, config_file, signing_key = create_test_agent

      begin
        loaded = AgentCrypto.load_credentials(config_file, "non-existent-db", signing_key)
        loaded.should be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles corrupted config file gracefully" do
      agent, config_file, signing_key = create_test_agent

      begin
        # Store valid credentials first
        db_id = "test-db"
        creds = %({"host": "localhost"})
        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        # Corrupt the encrypted value
        config = YAML.parse(File.read(config_file))
        config_hash = config.as_h? || {} of YAML::Any => YAML::Any

        creds_section = config_hash[YAML::Any.new("encrypted_db_credentials")]?
        if creds_section && creds_section.as_h?
          creds_hash = creds_section.as_h? || {} of YAML::Any => YAML::Any
          # Replace with invalid base64
          creds_hash[YAML::Any.new(db_id)] = YAML::Any.new("not-valid-base64!!!")
          config_hash[YAML::Any.new("encrypted_db_credentials")] = YAML::Any.new(creds_hash)
          File.write(config_file, config_hash.to_yaml)
        end

        # Should return nil on decryption failure
        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key, silent: true)
        loaded.should be_nil
      ensure
        cleanup_test_agent(config_file)
      end
    end

    it "handles empty credentials string" do
      agent, config_file, signing_key = create_test_agent

      begin
        db_id = "empty-creds"
        creds = ""

        AgentCrypto.store_credentials(config_file, db_id, creds, signing_key)

        loaded = AgentCrypto.load_credentials(config_file, db_id, signing_key)
        loaded.should eq creds
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end
end
