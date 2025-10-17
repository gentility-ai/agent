require "./spec_helper"

ENV["RATE_LIMIT_TEST_MODE"] = "true"

describe "Security Rate Limiting" do
  before_each do
    Security.lock
    Security.configure("password", "testpass", nil, 1800, true, true, "password", true, 5, "temporary", 900)
  end

  describe "backoff timing" do
    it "allows first attempt immediately" do
      Security.can_attempt?.should be_true
      Security.unlock("wrongpass").should be_false
    end

    it "enforces 1s backoff after first failure in test mode" do
      Security.unlock("wrongpass")
      Security.can_attempt?.should be_false
      Security.time_until_next_attempt.should be_close(1, 1)
    end

    it "enforces 2s backoff after second failure in test mode" do
      Security.unlock("wrongpass")  # First failure
      sleep (Security.time_until_next_attempt + 0.5).seconds  # Wait for backoff to expire
      Security.unlock("wrongpass")  # Second failure
      Security.time_until_next_attempt.should be_close(2, 1)
    end
  end

  describe "lockout behavior" do
    it "locks out after 5 failed attempts" do
      5.times do |i|
        Security.unlock("wrongpass")
        unless i == 4
          backoff = Security.time_until_next_attempt
          sleep (backoff + 0.5).seconds if backoff > 0
        end
      end
      Security.locked_out?.should be_true
    end

    it "allows successful unlock before lockout" do
      3.times do
        Security.unlock("wrongpass")
        backoff = Security.time_until_next_attempt
        sleep (backoff + 0.5).seconds if backoff > 0
      end
      Security.unlock("testpass").should be_true
      Security.failed_attempt_count.should eq 0
    end
  end
end
