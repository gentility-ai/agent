require "./spec_helper"

describe Security do
  # Reset security state before each test
  before_each do
    Security.configure("none", nil, nil, 1800, true)
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

  describe ".activated?" do
    context "when security mode is none" do
      it "always returns true" do
        Security.configure("none", nil, nil, 1800, true)
        Security.activated?.should be_true
      end
    end

    context "when security mode is password" do
      before_each do
        Security.configure("password", "testpass", nil, 1800, true)
      end

      it "returns false when not activated" do
        Security.activated?.should be_false
      end

      it "returns true after successful activation" do
        Security.activate("testpass").should be_true
        Security.activated?.should be_true
      end

      it "returns false after invalid activation attempt" do
        Security.activate("wrongpass").should be_false
        Security.activated?.should be_false
      end
    end

    context "when security mode is totp" do
      before_each do
        secret = generate_test_totp_secret
        Security.configure("totp", nil, secret, 1800, true)
      end

      it "returns false when not activated" do
        Security.activated?.should be_false
      end

      it "returns true after successful TOTP activation" do
        valid_code = generate_valid_totp_code(generate_test_totp_secret)
        Security.activate(valid_code).should be_true
        Security.activated?.should be_true
      end

      it "returns false with invalid TOTP code" do
        Security.activate("123456").should be_false
        Security.activated?.should be_false
      end
    end
  end

  describe ".activate" do
    it "activates with correct password" do
      Security.configure("password", "secret123", nil, 1800, true)
      Security.activate("secret123").should be_true
    end

    it "fails with incorrect password" do
      Security.configure("password", "secret123", nil, 1800, true)
      Security.activate("wrongpassword").should be_false
    end

    it "activates with valid TOTP code" do
      secret = generate_test_totp_secret
      Security.configure("totp", nil, secret, 1800, true)
      valid_code = generate_valid_totp_code(secret)
      Security.activate(valid_code).should be_true
    end
  end

  describe ".deactivate" do
    it "deactivates security" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.activate("testpass")
      Security.activated?.should be_true
      
      Security.deactivate
      Security.activated?.should be_false
    end
  end

  describe ".time_remaining" do
    it "returns -1 when security mode is none" do
      Security.configure("none", nil, nil, 1800, true)
      Security.time_remaining.should eq -1
    end

    it "returns 0 when not activated" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.time_remaining.should eq 0
    end

    it "returns positive value when activated" do
      Security.configure("password", "testpass", nil, 1800, true)
      Security.activate("testpass")
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
      config = Security.export_config
      
      config["success"].should be_true
      config["security_config"]["mode"].should eq "password"
      config["security_config"]["password"].should eq "testpass"
    end
  end
end