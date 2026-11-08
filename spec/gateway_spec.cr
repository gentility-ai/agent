require "./spec_helper"

# Stands in for `sudo -n <helper>`: answers with the arguments it was given.
ECHO_HELPER = ["/bin/sh", "-c", %(printf '{"argv":["%s","%s","%s"],"count":%s}' "$1" "$2" "$3" "$#"), "helper"]

describe Gateway do
  describe ".install" do
    params = JSON.parse(%({"move_id": "m", "bundle_url": "u", "sha256": "s", "extra": "/etc/shadow"}))

    it "hands the helper exactly the three words, in order, and answers with its JSON" do
      answer = Gateway.install(params, ECHO_HELPER).as(JSON::Any)
      answer["argv"].should eq(JSON.parse(%(["m","u","s"])))
      answer["count"].should eq(3)
    end

    it "asks for the three words when one is missing" do
      Gateway.install(JSON.parse(%({"move_id": "m", "sha256": "s"})), ECHO_HELPER)
        .should eq({"error" => "Missing move_id, bundle_url or sha256 parameter"})
    end

    it "says so when the helper is killed by a signal" do
      expect_raises(Exception, "Gateway helper gave no answer (killed by a signal)") do
        Gateway.install(params, ["/bin/sh", "-c", "kill -9 $$"])
      end
    end

    it "raises when the helper gives no JSON answer" do
      expect_raises(Exception, "Gateway helper gave no answer (exit 1): sudo: a password is required") do
        Gateway.install(params, ["/bin/sh", "-c", "echo sudo: a password is required >&2; exit 1"])
      end
    end
  end

  describe ".current" do
    it "is nil when the host has no bundle record" do
      Gateway.current("/nonexistent/current.json").should be_nil
    end

    it "is the helper's record when there is one" do
      path = File.tempname("current", ".json")
      File.write(path, %({"bundle":"8.0.60-0.2.0","upstream_version":"8.0.60","plugin_version":"0.2.0"}))
      Gateway.current(path).try(&.["bundle"]).should eq("8.0.60-0.2.0")
    ensure
      File.delete?(path) if path
    end
  end
end
