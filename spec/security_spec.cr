require "./spec_helper"

describe Security do
  # Reset security state before each test
  before_each do
    Security.lock  # Ensure clean locked state
    Security.configure("none", nil, nil, 1800, true, true, "password")
  end

  describe ".configure" do
    it "sets security mode to none" do
      Security.configure("none", nil, nil, 1800, true)
      Security.mode.should eq "none"
    end

    it "sets security mode to password" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.mode.should eq "password"
    end

    it "sets security mode to totp" do
      secret = generate_test_totp_secret
      Security.configure("totp", nil, secret, 1800, true)
      Security.mode.should eq "totp"
    end
  end

  describe ".unlocked?" do
    context "when security mode is none" do
      it "always returns true" do
        Security.configure("none", nil, nil, 1800, true)
        Security.unlocked?.should be_true
      end
    end

    context "when security mode is password" do
      before_each do
        Security.configure("password", "testpass", nil, 1800, true)
      end

      it "returns false when not unlocked" do
        Security.unlocked?.should be_false
      end

      it "returns true after successful unlock" do
        Security.unlock("testpass").should be_true
        Security.unlocked?.should be_true
      end

      it "returns false after invalid unlock attempt" do
        Security.unlock("wrongpass").should be_false
        Security.unlocked?.should be_false
      end
    end

    context "when security mode is totp" do
      before_each do
        secret = generate_test_totp_secret
        Security.configure("totp", nil, secret, 1800, true)
      end

      it "returns false when not unlocked" do
        Security.unlocked?.should be_false
      end

      it "returns true after successful TOTP unlock" do
        valid_code = generate_valid_totp_code(generate_test_totp_secret)
        Security.unlock(valid_code).should be_true
        Security.unlocked?.should be_true
      end

      it "returns false with invalid TOTP code" do
        Security.unlock("123456").should be_false
        Security.unlocked?.should be_false
      end
    end
  end

  describe ".activate" do
    it "activates with correct password" do
      Security.configure("password", "secret123", nil, 1800, true)
      Security.unlock("secret123").should be_true
    end

    it "fails with incorrect password" do
      Security.configure("password", "secret123", nil, 1800, true)
      Security.unlock("wrongpassword").should be_false
    end

    it "activates with valid TOTP code" do
      secret = generate_test_totp_secret
      Security.configure("totp", nil, secret, 1800, true)
      valid_code = generate_valid_totp_code(secret)
      Security.unlock(valid_code).should be_true
    end
  end

  describe ".deactivate" do
    it "locks security" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.unlock("testpass")
      Security.unlocked?.should be_true
      
      Security.lock
      Security.unlocked?.should be_false
    end
  end

  describe ".time_remaining" do
    it "returns -1 when security mode is none" do
      Security.configure("none", nil, nil, 1800, true)
      Security.time_remaining.should eq -1
    end

    it "returns -1 when not active (locked)" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.lock  # Ensure it's locked (not active)
      # When locked (not active), time_remaining returns -1
      Security.time_remaining.should eq -1
    end

    it "returns positive value when unlocked" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.unlock("testpass")
      Security.time_remaining.should be > 0
    end
  end

  describe ".status" do
    it "returns correct status for none mode" do
      Security.configure("none", nil, nil, 1800, true)
      status = Security.status
      
      status["security_enabled"].should be_false
      status["security_mode"].should eq "none"
      status["active"].should be_true
    end

    it "returns correct status for password mode" do
      Security.configure("password", "testpass", nil, 1800, true)
      status = Security.status
      
      status["security_enabled"].should be_true
      status["security_mode"].should eq "password"
      status["active"].should be_false
    end
  end

  describe ".validate_promiscuous_auth" do
    context "when promiscuous mode is enabled with password auth" do
      before_each do
        Security.configure("password", "testpass", nil, 1800, true, true, "password")
      end

      it "validates correct password" do
        Security.validate_promiscuous_auth("testpass").should be_true
      end

      it "rejects incorrect password" do
        Security.validate_promiscuous_auth("wrongpass").should be_false
      end
    end

    context "when promiscuous mode is disabled" do
      before_each do
        Security.configure("password", "testpass", nil, 1800, true, false, "password")
      end

      it "rejects any credential" do
        Security.validate_promiscuous_auth("testpass").should be_false
      end
    end
  end

  describe ".export_config" do
    it "exports security configuration" do
      Security.configure("password", "testpass", nil, 1800, true, true, "password")
      result = Security.export_config

      result.has_key?("success").should be_true
      result.has_key?("security_config").should be_true
      result.size.should eq 2
    end
  end
end