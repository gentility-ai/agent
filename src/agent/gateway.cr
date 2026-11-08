require "json"

# The agent's half of a gateway move (the gateway bundle contract): it hands
# the root helper the three words the server sent, through the one sudoers line
# the package ships, and answers with the helper's JSON. The helper verifies
# everything itself; the agent adds nothing to what it is asked.
module Gateway
  HELPER  = "/usr/libexec/gentility/gentility-gateway-install"
  CURRENT = "/var/lib/gentility-gateway/current.json"

  def self.install(params : JSON::Any?, helper = ["sudo", "-n", HELPER])
    words = {"move_id", "bundle_url", "sha256"}.map { |key| params.try(&.[key]?).try(&.as_s?) }
    return {"error" => "Missing move_id, bundle_url or sha256 parameter"} if words.any?(&.nil?)

    output = IO::Memory.new
    status = Process.run(helper[0], helper[1..] + words.map(&.not_nil!).to_a,
      output: output, error: Process::Redirect::Inherit)
    answer = JSON.parse(output.to_s) rescue nil
    raise "Gateway helper gave no answer (exit #{status.exit_code})" unless answer.try(&.as_h?)
    answer
  end

  # What runs on this host, as the helper last recorded it; nil when the host
  # has no bundle record.
  def self.current(path = CURRENT) : JSON::Any?
    JSON.parse(File.read(path)) if File.exists?(path)
  rescue JSON::ParseException | File::Error
    nil
  end
end
