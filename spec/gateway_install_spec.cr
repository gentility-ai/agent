require "spec"
require "http/server"
require "../src/gateway_install/installer"

# Builds tar streams by hand, so a test can write entries a real bundle never
# would (directories, paths) without depending on the host's tar.
module TarWriter
  def self.build(entries : Array({String, String}), type : Char = '0') : Bytes
    io = IO::Memory.new
    entries.each do |name, body|
      header = Bytes.new(512)
      put(header, 0, name)
      put(header, 100, "0000644\0")
      put(header, 108, "0000000\0")
      put(header, 116, "0000000\0")
      put(header, 124, "%011o\0" % body.bytesize)
      put(header, 136, "00000000000\0")
      header[156] = type.ord.to_u8
      put(header, 257, "ustar\0" + "00")
      put(header, 148, " " * 8)
      put(header, 148, "%06o\0 " % header.sum(0))
      io.write(header)
      io.write(body.to_slice)
      io.write(Bytes.new((512 - body.bytesize % 512) % 512))
    end
    io.write(Bytes.new(1024))
    io.to_slice
  end

  private def self.put(header : Bytes, at : Int32, text : String) : Nil
    text.to_slice.copy_to(header + at)
  end
end

# The client key with no harness prefix in the fake host's config.yaml. A
# plain word, so a reason built from the proxy's error type could carry it.
SENTINEL = "gateway_sentinel_quokka_marmalade"
SCOPED   = {403, %({"error":{"type":"key_scope","message":"this gateway key is for no harness"}})}

# A host whose cliproxyapi "runs" whatever the drop-in and plugin name at
# restart: a plugin file reading "plugin <version>" registers, anything else
# does not, and the process runs the binary the drop-in names.
class FakeSystem < GatewayInstaller::System
  getter fetches = 0
  getter restarts = 0
  getter clock = Time.utc(2026, 11, 8)
  getter isolated_with : Array(String)? = nil
  property bundles = {} of String => Bytes
  property placement = GatewayInstaller::Placement::Isolated
  # Whether cliproxyapi has a main process (at boot, before it starts, not).
  property running = true
  # The process keeps running the old binary, as when the unit was not reloaded.
  property stale_exe = false
  # The process falls over and systemd restarts it, again and again.
  property flapping = false
  # The journal lacks the config watcher's line after this restart.
  property journal_without_watcher_at : Int32? = nil
  # The proxy logs to main.log, so its watcher's line is there and not in the
  # journal, after this restart.
  property watcher_in_main_log_at : Int32? = nil
  # The journal cannot be read after this restart.
  property journal_fails_at : Int32? = nil
  # Called at each restart, with its number.
  property on_restart : Proc(Int32, Nil)? = nil
  # What the proxy answers the key scope canary, by restart number.
  property canary_answer : Proc(Int32, {Int32, String}?) = ->(_n : Int32) { SCOPED.as({Int32, String}?) }
  getter canaries = [] of {String, String, String}
  # Where the proxy answers, and the addresses this host holds besides loopback.
  property listen = "http://[::1]:8317"
  property local = [] of String
  @journal = ""
  @pid = 100_i64
  @nrestarts = 0_i64
  @exe : String? = "/opt/cliproxyapi/8.0.47/cli-proxy-api"

  def initialize(@root : String)
  end

  def placement(move_id : String) : GatewayInstaller::Placement
    @placement
  end

  def isolate(args : Array(String)) : {Int32, String}
    @isolated_with = args
    {0, %({"from":"the move unit"})}
  end

  def fetch(url : String, dest : String) : Nil
    @fetches += 1
    File.write(dest, @bundles[url])
  end

  def daemon_reload : Bool
    true
  end

  def restart : Bool
    @restarts += 1
    @on_restart.try &.call(@restarts)
    @pid += 1
    @exe = File.read(@root + GatewayInstaller::DROP_IN)[GatewayInstaller::PROXY_PATH]? unless @stale_exe
    plugin = File.read("#{@root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so")
    @journal = if version = plugin.lchop?("plugin ")
                 "plugin registered plugin_id=gentility-usage name=usage version=#{version}\n" \
                 "API server started successfully on: [::1]:8317\n" \
                 "#{GatewayInstaller::WATCHER}\n"
               else
                 "plugin load failed\nAPI server started successfully on: [::1]:8317\n"
               end
    true
  end

  def unit_state : {Int64, Int64}?
    @nrestarts += 1 if @flapping
    {@running ? @pid : 0_i64, @nrestarts}
  end

  def exe(pid : Int64) : String?
    @exe
  end

  def journal_since(since : Time) : String
    raise IO::Error.new("journalctl: no such file") if @restarts == @journal_fails_at
    return @journal.sub(GatewayInstaller::WATCHER, "") if @restarts == @journal_without_watcher_at
    if @restarts == @watcher_in_main_log_at
      File.write(@root + GatewayInstaller::MAIN_LOG, "[info ] #{GatewayInstaller::WATCHER}\n", mode: "a")
      return @journal.sub(GatewayInstaller::WATCHER, "")
    end
    @journal
  end

  def models_status(url : String) : Int32?
    url == "#{@listen}/v1/models" ? 401 : nil
  end

  def canary(url : String, key : String, model : String) : {Int32, String}?
    @canaries << {url, key, model}
    @canary_answer.call(@restarts)
  end

  def local?(address : Socket::IPAddress) : Bool
    @local.includes?(address.address)
  end

  def now : Time
    @clock
  end

  def ticks : Time::Span
    @clock - Time.utc(2026, 11, 8)
  end

  def sleep(span : Time::Span) : Nil
    @clock += span
  end
end

MOVE   = "019a5b2c-0000-7000-8000-000000000001"
URL    = "https://github.com/gentility-ai/gateway/releases/download/gateway-8.0.60-0.2.0/bundle.tar"
DROPIN = "[Service]\nExecStart=\nExecStart=/opt/cliproxyapi/8.0.47/cli-proxy-api -config /var/lib/cliproxyapi/config.yaml\n"
CONFIG = <<-YAML
  server:
    host: "::1"
    port: 8317
  access:
    api-keys:
      - "omp_4f2a"
      - "#{SENTINEL}"
      - "claude_9b1c"
  api-keys:
    openai-compatibility:
      - name: "retired"
        disabled: true
        models: [{name: "old-model"}]
      - name: "omp"
        prefix: "gw"
        models:
          - name: "glm-5"
            alias: "omp-glm"
          - name: "kimi-k2"
  YAML
SENTINEL_LINE = %(    - "#{SENTINEL}"\n)

def key_id(key : Ed25519::SigningKey) : String
  key.verify_key.key_bytes[0, 8].hexstring
end

def gzip(entries : Array({String, String})) : Bytes
  io = IO::Memory.new
  Compress::Gzip::Writer.open(io) { |gz| gz.write(TarWriter.build(entries)) }
  io.to_slice
end

def sha256(bytes : Bytes | String) : String
  Digest::SHA256.new.update(bytes.to_slice).hexfinal
end

# A bundle as the packaging repo would build it, with knobs to spoil it.
def bundle(key : Ed25519::SigningKey,
           plugin_version = "0.5.0",
           plugin = "plugin #{plugin_version}",
           kind = "gateway",
           format = 1,
           signing_key = key,
           sig_key_id = key_id(key),
           shipped_plugin : String? = nil,
           extra = [] of {String, String},
           upstream = "8.0.60",
           proxy = "proxy #{upstream}") : Bytes
  archive = String.new(gzip([{"cli-proxy-api", proxy}, {"LICENSE", "MIT"}]))
  manifest = {
    "kind"     => kind,
    "format"   => format,
    "bundle"   => "#{upstream}-#{plugin_version}",
    "upstream" => {"repo" => "router-for-me/CLIProxyAPI", "version" => upstream,
                   "archive" => "CLIProxyAPI_#{upstream}_linux_amd64.tar.gz", "sha256" => sha256(archive)},
    "plugin" => {"id" => "gentility-usage", "version" => plugin_version, "commit" => "abc",
                 "file" => "gentility-usage.so", "sha256" => sha256(plugin)},
    "unknown_field" => "ignored",
  }.to_json
  sig = {"key_id" => sig_key_id, "signature" => Base64.strict_encode(signing_key.sign(manifest))}.to_json
  TarWriter.build([
    {"manifest.json", manifest},
    {"manifest.sig", sig},
    {"CLIProxyAPI_#{upstream}_linux_amd64.tar.gz", archive},
    {"gentility-usage.so", shipped_plugin || plugin},
  ] + extra)
end

# A gateway host under a temp root, running 8.0.47 with plugin 0.1.0.
def with_host(&)
  root = File.join(Dir.tempdir, "gateway-install-#{Random::Secure.hex(6)}")
  key = Ed25519::SigningKey.new
  {
    "/etc/gentility-gateway/keys.json"                   => {"keys" => {key_id(key) => Base64.strict_encode(key.verify_key.key_bytes)}}.to_json,
    GatewayInstaller::DROP_IN                            => DROPIN,
    GatewayInstaller::CONFIG                             => CONFIG,
    "#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so" => "plugin 0.1.0",
    "/opt/cliproxyapi/8.0.47/cli-proxy-api"              => "proxy 8.0.47",
    GatewayInstaller::CURRENT                            => {"bundle" => "8.0.47-0.1.0", "upstream_version" => "8.0.47", "plugin_version" => "0.1.0"}.to_json,
  }.each do |path, content|
    Dir.mkdir_p(File.dirname(root + path))
    File.write(root + path, content)
  end
  system = FakeSystem.new(root)
  installer = GatewayInstaller::Installer.new(system, root, check_within: 60.seconds, poll_every: 2.seconds)
  yield root, key, system, installer
ensure
  FileUtils.rm_rf(root) if root
end

# The host as a move to plugin 0.5.0 left it: a previous version with the scope.
def scoped_previous(root : String) : Nil
  File.write("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so", "plugin 0.5.0")
  File.write(root + GatewayInstaller::CURRENT, {"bundle" => "8.0.47-0.5.0", "upstream_version" => "8.0.47", "plugin_version" => "0.5.0"}.to_json)
end

def install(installer, system, bytes : Bytes, sha = sha256(bytes), move = MOVE) : {Int32, JSON::Any}
  system.bundles[URL] = bytes
  status, output = installer.run([move, URL, sha])
  {status, JSON.parse(output)}
end

def host_unchanged(root : String, system : FakeSystem)
  File.read(root + GatewayInstaller::DROP_IN).should eq(DROPIN)
  File.read("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.1.0")
  File.exists?(root + "/opt/cliproxyapi/8.0.60").should be_false
  system.restarts.should eq(0)
end

describe GatewayInstaller::Installer do
  it "moves to a signed bundle and records what runs" do
    with_host do |root, key, system, installer|
      status, answer = install(installer, system, bundle(key))

      status.should eq(0)
      answer["result"].should eq("moved")
      answer["reason"].should eq("")
      answer["running"].should eq(JSON.parse(%({"bundle":"8.0.60-0.5.0","upstream_version":"8.0.60","plugin_version":"0.5.0"})))
      answer["key_scope"].should eq("live")
      answer["previous"]["bundle"].should eq("8.0.47-0.1.0")

      File.read(root + GatewayInstaller::DROP_IN).should contain("ExecStart=/opt/cliproxyapi/8.0.60/cli-proxy-api -config")
      File.read(root + "/opt/cliproxyapi/8.0.60/cli-proxy-api").should eq("proxy 8.0.60")
      File.read(root + "/opt/cliproxyapi/8.0.47/cli-proxy-api").should eq("proxy 8.0.47")
      File.read("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.5.0")
      File.read("#{root}/var/lib/gentility-gateway/previous/2").should eq("plugin 0.1.0")
      JSON.parse(File.read(root + GatewayInstaller::CURRENT)).should eq(JSON.parse(%({"bundle":"8.0.60-0.5.0","upstream_version":"8.0.60","plugin_version":"0.5.0","key_scope":"live"})))
      JSON.parse(File.read("#{root}/var/lib/gentility-gateway/moves/#{MOVE}.json")).should eq(answer)
      File.exists?("#{root}/var/lib/gentility-gateway/staging/#{MOVE}").should be_false
    end
  end

  it "finds the config watcher's line in main.log when the proxy logs to a file" do
    with_host do |root, key, system, installer|
      Dir.mkdir_p(File.dirname(root + GatewayInstaller::MAIN_LOG))
      File.write(root + GatewayInstaller::MAIN_LOG, "[info ] an earlier start\n")
      system.watcher_in_main_log_at = 1
      _, answer = install(installer, system, bundle(key))
      answer["result"].should eq("moved")
    end
  end

  it "reports a null previous for the first move from a hand install" do
    with_host do |root, key, system, installer|
      File.delete(root + GatewayInstaller::CURRENT)
      _, answer = install(installer, system, bundle(key))
      answer["result"].should eq("moved")
      answer["previous"].raw.should be_nil
    end
  end

  it "answers a repeated move id from its record without installing twice" do
    with_host do |root, key, system, installer|
      _, first = install(installer, system, bundle(key))
      status, again = install(installer, system, bundle(key))

      status.should eq(0)
      again.should eq(first)
      system.fetches.should eq(1)
      system.restarts.should eq(1)
    end
  end

  it "rolls back when the new plugin does not register" do
    with_host do |root, key, system, installer|
      _, answer = install(installer, system, bundle(key, plugin: "broken"))

      answer["result"].should eq("rolled_back")
      answer["reason"].as_s.should start_with("plugin gentility-usage 0.5.0 did not register")
      answer["reason"].as_s.should_not contain("previous version failed")
      answer["running"]["bundle"].should eq("8.0.47-0.1.0")
      system.restarts.should eq(2)
      File.read(root + GatewayInstaller::DROP_IN).should eq(DROPIN)
      File.read("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.1.0")
      JSON.parse(File.read(root + GatewayInstaller::CURRENT))["bundle"].should eq("8.0.47-0.1.0")
    end
  end

  it "waits up to the check's deadline before rolling back" do
    with_host do |root, key, system, installer|
      install(installer, system, bundle(key, plugin: "broken"))
      # 60 s for the new version's check, then the previous one's 15 s settle.
      (system.clock - Time.utc(2026, 11, 8)).should eq(75.seconds)
    end
  end

  it "says so when the previous version fails its check too" do
    with_host do |root, key, system, installer|
      File.write("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so", "broken before")
      _, answer = install(installer, system, bundle(key, plugin: "broken"))
      answer["result"].should eq("rolled_back")
      answer["reason"].as_s.should contain("the previous version failed its check too")
      answer["running"].raw.should be_nil
      answer["previous"]["bundle"].should eq("8.0.47-0.1.0")
      # Nothing known runs, so there is no record of what does.
      File.exists?(root + GatewayInstaller::CURRENT).should be_false
    end
  end

  it "refuses when it cannot tell whether it runs in a unit of its own" do
    with_host do |root, key, system, installer|
      system.placement = GatewayInstaller::Placement::Unknown
      status, answer = install(installer, system, bundle(key))
      status.should eq(1)
      answer["result"].should eq("refused")
      answer["reason"].should eq("cannot tell whether the helper runs in a unit of its own")
      system.isolated_with.should be_nil
      system.fetches.should eq(0)
    end
  end

  it "runs the move in its own unit when started anywhere else" do
    with_host do |root, key, system, installer|
      system.placement = GatewayInstaller::Placement::Outside
      status, output = installer.run([MOVE, URL, "a" * 64])
      {status, output}.should eq({0, %({"from":"the move unit"})})
      system.isolated_with.should eq([MOVE, URL, "a" * 64])
      Dir.exists?("#{root}/var/lib/gentility-gateway/moves").should be_false
    end
  end

  describe "fails the check, and rolls back, when" do
    it "the proxy runs a binary other than the one the drop-in names" do
      with_host do |root, key, system, installer|
        system.stale_exe = true
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with(
          "cliproxyapi runs /opt/cliproxyapi/8.0.47/cli-proxy-api, not /opt/cliproxyapi/8.0.60/cli-proxy-api")
        File.read(root + GatewayInstaller::DROP_IN).should eq(DROPIN)
      end
    end

    it "the proxy's config watcher does not start" do
      with_host do |root, key, system, installer|
        system.journal_without_watcher_at = 1
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with("the config watcher did not start")
      end
    end

    it "an earlier start's watcher line in main.log" do
      with_host do |root, key, system, installer|
        Dir.mkdir_p(File.dirname(root + GatewayInstaller::MAIN_LOG))
        File.write(root + GatewayInstaller::MAIN_LOG, "[info ] #{GatewayInstaller::WATCHER}\n")
        system.journal_without_watcher_at = 1
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with("the config watcher did not start")
      end
    end

    it "the proxy restarts after passing" do
      with_host do |root, key, system, installer|
        system.flapping = true
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with("cliproxyapi restarted within 15 s of passing its check")
      end
    end

    it "config.yaml is not a mapping" do
      with_host do |root, key, system, installer|
        system.on_restart = ->(n : Int32) { File.write(root + GatewayInstaller::CONFIG, "- not\n- a mapping\n") if n == 1 }
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with("config.yaml is unreadable")
        File.read(root + GatewayInstaller::CONFIG).should eq(CONFIG)
      end
    end

    it "the check itself raises" do
      with_host do |root, key, system, installer|
        system.journal_fails_at = 1
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        answer["reason"].as_s.should start_with("the check could not run: journalctl: no such file")
        answer["running"]["bundle"].should eq("8.0.47-0.1.0")
        File.read(root + GatewayInstaller::DROP_IN).should eq(DROPIN)
      end
    end
  end

  describe "the key scope canary" do
    it "is the sentinel asking an openai-compatibility model, after the check passes" do
      with_host do |root, key, system, installer|
        install(installer, system, bundle(key))
        system.canaries.should eq([{"http://[::1]:8317/v1/chat/completions", SENTINEL, "gw/omp-glm"}])
        JSON.parse(File.read(root + GatewayInstaller::CURRENT))["key_scope"].should eq("live")
      end
    end

    {
      "answers 200"                     => {->(_n : Int32) { {200, %({"choices":[]})}.as({Int32, String}?) }, "200"},
      "answers 403 of another type"     => {->(_n : Int32) { {403, %({"error":{"type":"forbidden"}})}.as({Int32, String}?) }, "403"},
      "answers 403 without JSON"        => {->(_n : Int32) { {403, "Forbidden"}.as({Int32, String}?) }, "403"},
      "answers 401, refusing the key"   => {->(_n : Int32) { {401, %({"error":{"type":"authentication_error"}})}.as({Int32, String}?) }, "401"},
      "gives no answer within its time" => {->(_n : Int32) { nil.as({Int32, String}?) }, "no answer within 20 s"},
    }.each do |what, (answer, fault)|
      it "rolls back when the new version #{what}" do
        with_host do |root, key, system, installer|
          system.canary_answer = answer
          _, moved = install(installer, system, bundle(key))
          moved["result"].should eq("rolled_back")
          moved["reason"].should eq("the key scope is not live: #{fault}")
          File.read(root + GatewayInstaller::DROP_IN).should eq(DROPIN)
          File.read("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.1.0")
          moved["running"]["bundle"].should eq("8.0.47-0.1.0")
          # The previous plugin, 0.1.0, has no scope, so it is not asked.
          system.canaries.size.should eq(1)
          moved["key_scope"].should eq("unchecked")
          moved["running"]["key_scope"]?.should be_nil
          JSON.parse(File.read(root + GatewayInstaller::CURRENT))["key_scope"].should eq("unchecked")
        end
      end
    end

    it "says whether a previous version that has the scope is live, after a roll back to it" do
      with_host do |root, key, system, installer|
        scoped_previous(root)
        system.canary_answer = ->(n : Int32) { n == 1 ? {200, "{}"}.as({Int32, String}?) : SCOPED }
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("rolled_back")
        system.canaries.size.should eq(2)
        answer["key_scope"].should eq("live")
        JSON.parse(File.read(root + GatewayInstaller::CURRENT))["key_scope"].should eq("live")
      end
    end

    it "asks only the previous version when the new one fails its check" do
      with_host do |root, key, system, installer|
        scoped_previous(root)
        system.canary_answer = ->(_n : Int32) { {200, "{}"}.as({Int32, String}?) }
        _, answer = install(installer, system, bundle(key, plugin: "broken"))
        answer["reason"].as_s.should start_with("plugin gentility-usage 0.5.0 did not register")
        system.canaries.size.should eq(1)
        answer["key_scope"].should eq("absent")
      end
    end

    describe "asks a target plugin by its version:" do
      {"0.5.0" => true, "0.5.0-rc" => true, "0.10.0" => true, "v0.5" => true, "next" => true, "0.4.99" => false, "0.4.0" => false}.each do |version, asked|
        it "#{version} is #{asked ? "" : "not "}asked" do
          with_host do |root, key, system, installer|
            _, answer = install(installer, system, bundle(key, plugin_version: version))
            answer["result"].should eq("moved")
            system.canaries.size.should eq(asked ? 1 : 0)
            answer["key_scope"].should eq(asked ? "live" : "unchecked")
          end
        end
      end
    end

    describe "refuses the move before the host changes when config.yaml has" do
      {
        "no sentinel"               => {"", 0},
        "two keys without a prefix" => {"#{SENTINEL_LINE}    - other\n", 2},
      }.each do |what, (lines, count)|
        it what do
          with_host do |root, key, system, installer|
            File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(SENTINEL_LINE, lines))
            reason = "access.api-keys has #{count} keys without a harness prefix; expected exactly one, the sentinel"
            _, answer = install(installer, system, bundle(key))
            answer["result"].should eq("refused")
            answer["reason"].should eq(reason)
            host_unchanged(root, system)
          end
        end
      end

      it "no openai-compatibility model a login serves" do
        with_host do |root, key, system, installer|
          File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(/    - name: "omp".*/m, ""))
          _, answer = install(installer, system, bundle(key))
          answer["reason"].should eq("config.yaml names no openai-compatibility model")
          host_unchanged(root, system)
        end
      end

      {
        "another host's address" => {"config.yaml's host is not an address of this host", %(host: "203.0.113.7")},
        "a name"                 => {"config.yaml's host is not an IP address", %(host: "evil.example")},
        "a name with a path"     => {"config.yaml's host is not an IP address", %(host: "evil.example/x?")},
        "a name with userinfo"   => {"config.yaml's host is not an IP address", %(host: "u@evil.example")},
        "userinfo on loopback"   => {"config.yaml's host is not an IP address", %(host: "u@127.0.0.1")},
      }.each do |what, (reason, host)|
        it "a listen address of #{what}" do
          with_host do |root, key, system, installer|
            File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(%(host: "::1"), host))
            _, answer = install(installer, system, bundle(key))
            answer["result"].should eq("refused")
            answer["reason"].should eq(reason)
            system.canaries.should be_empty
            host_unchanged(root, system)
          end
        end
      end

      it "a listen port out of range" do
        with_host do |root, key, system, installer|
          File.write(root + GatewayInstaller::CONFIG, CONFIG.sub("port: 8317", "port: 70000"))
          _, answer = install(installer, system, bundle(key))
          answer["reason"].should eq("config.yaml's port is not a port")
          host_unchanged(root, system)
        end
      end

      it "another host's address, even for a plugin the canary skips" do
        with_host do |root, key, system, installer|
          File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(%(host: "::1"), %(host: "203.0.113.7")))
          _, answer = install(installer, system, bundle(key, plugin_version: "0.4.0"))
          answer["reason"].should eq("config.yaml's host is not an address of this host")
          host_unchanged(root, system)
        end
      end
    end

    {
      %(host: "[fd06:6e7:0:2::6]") => "http://[fd06:6e7:0:2::6]:8317",
      %(host: "::")                => "http://[::1]:8317",
      %(host: "0.0.0.0")           => "http://127.0.0.1:8317",
      %(host: "")                  => "http://127.0.0.1:8317",
    }.each do |host, listen|
      it "asks #{listen} for a listen address of #{host}" do
        with_host do |root, key, system, installer|
          system.local = ["fd06:6e7:0:2::6"]
          system.listen = listen
          File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(%(host: "::1"), host))
          _, answer = install(installer, system, bundle(key))
          answer["result"].should eq("moved")
          system.canaries.map(&.[0]).should eq(["#{listen}/v1/chat/completions"])
        end
      end
    end

    it "never writes the sentinel, or a piece of it, into an answer, a record or current.json" do
      with_host do |root, key, system, installer|
        outputs = [] of String
        # The proxy even names the key in its refusal, whole, in part, or upper-cased.
        echoes = [SENTINEL, SENTINEL[1..-2], SENTINEL.upcase].map do |echo|
          {403, %({"error":{"type":"#{echo}","message":"bad key #{echo}"}})}
        end
        ([SCOPED] + echoes + [{200, SENTINEL}]).each_with_index do |answer, n|
          system.canary_answer = ->(_n : Int32) { answer.as({Int32, String}?) }
          system.bundles[URL] = bundle(key, upstream: "8.0.6#{n}")
          outputs << installer.run(["019a5b2c-0000-7000-8000-00000000000#{n}", URL, sha256(system.bundles[URL])])[1]
        end
        File.write(root + GatewayInstaller::CONFIG, CONFIG.sub(SENTINEL_LINE, "#{SENTINEL_LINE}    - other\n"))
        outputs << installer.run(["019a5b2c-0000-7000-8000-000000000009", URL, sha256(system.bundles[URL])])[1]

        system.canaries.map(&.[1]).uniq.should eq([SENTINEL])
        JSON.parse(outputs[0])["result"].should eq("moved")
        outputs[1..4].each { |output| JSON.parse(output)["reason"].as_s.should start_with("the key scope is not live: ") }
        JSON.parse(outputs[5])["result"].should eq("refused")
        # Only the kept copy of config.yaml itself holds it.
        written = Dir.glob("#{root}/var/lib/gentility-gateway/**/*", match: :dot_files)
          .reject { |path| path.starts_with?("#{root}/var/lib/gentility-gateway/previous/") || File.directory?(path) }
        written.should contain("#{root}#{GatewayInstaller::CURRENT}")
        (outputs + written.map { |path| File.read(path) }).each(&.downcase.should_not(contain("quokka")))
        GatewayInstaller::Canary.new("u", SENTINEL, "m").inspect.should_not contain(SENTINEL)
        GatewayInstaller::Canary.new("u", SENTINEL, "m").to_s.should_not contain(SENTINEL)
      end
    end
  end

  describe "a move cut off midway" do
    it "is rolled back by the next helper run, which records it as interrupted" do
      with_host do |root, key, system, installer|
        # The host as a helper killed at the restart leaves it: switched, with
        # its marker written and no record.
        cut = "#{root}-cut"
        system.on_restart = ->(n : Int32) { FileUtils.cp_r(root, cut) if n == 1; nil }
        install(installer, system, bundle(key))
        begin
          File.read(cut + GatewayInstaller::DROP_IN).should contain("8.0.60")
          File.exists?(cut + GatewayInstaller::MARKER).should be_true

          later = FakeSystem.new(cut)
          next_move = "019a5b2c-0000-7000-8000-000000000002"
          _, answer = install(GatewayInstaller::Installer.new(later, cut), later, bundle(key, plugin: "broken"), move: next_move)

          interrupted = JSON.parse(File.read("#{cut}/var/lib/gentility-gateway/moves/#{MOVE}.json"))
          interrupted["result"].should eq("rolled_back")
          interrupted["reason"].should eq("interrupted")
          interrupted["running"]["bundle"].should eq("8.0.47-0.1.0")
          File.exists?(cut + GatewayInstaller::MARKER).should be_false
          JSON.parse(File.read(cut + GatewayInstaller::CURRENT))["bundle"].should eq("8.0.47-0.1.0")
          # The next move then ran from the restored host, and rolled back to it.
          answer["result"].should eq("rolled_back")
          answer["previous"]["bundle"].should eq("8.0.47-0.1.0")
          File.read(cut + GatewayInstaller::DROP_IN).should eq(DROPIN)
          File.read("#{cut}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.1.0")
          File.exists?(cut + "/opt/cliproxyapi/8.0.60/cli-proxy-api").should be_false
        ensure
          FileUtils.rm_rf(cut)
        end
      end
    end

    it "is put back at boot, before the proxy starts, without a restart" do
      with_host do |root, key, system, installer|
        cut = "#{root}-cut"
        system.on_restart = ->(n : Int32) { FileUtils.cp_r(root, cut) if n == 1; nil }
        install(installer, system, bundle(key))
        begin
          boot = FakeSystem.new(cut)
          boot.running = false
          status, output = GatewayInstaller::Installer.new(boot, cut).run(["--recover"])

          status.should eq(0)
          answer = JSON.parse(output)
          answer["move_id"].should eq(MOVE)
          answer["result"].should eq("rolled_back")
          answer["reason"].should eq("interrupted")
          answer["key_scope"].should eq("unchecked")
          boot.restarts.should eq(0)
          File.read(cut + GatewayInstaller::DROP_IN).should eq(DROPIN)
          File.read("#{cut}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.1.0")
          JSON.parse(File.read(cut + GatewayInstaller::CURRENT))["bundle"].should eq("8.0.47-0.1.0")
          File.exists?(cut + GatewayInstaller::MARKER).should be_false
          # A second boot finds nothing to do.
          GatewayInstaller::Installer.new(boot, cut).run(["--recover"]).should eq({0, ""})
        ensure
          FileUtils.rm_rf(cut)
        end
      end
    end

    it "is put back at boot without asking the canary, even when the proxy runs" do
      with_host do |root, key, system, installer|
        scoped_previous(root)
        cut = "#{root}-cut"
        system.on_restart = ->(n : Int32) { FileUtils.cp_r(root, cut) if n == 1; nil }
        install(installer, system, bundle(key))
        begin
          boot = FakeSystem.new(cut)
          status, output = GatewayInstaller::Installer.new(boot, cut).run(["--recover"])
          status.should eq(0)
          answer = JSON.parse(output)
          answer["result"].should eq("rolled_back")
          answer["running"]["bundle"].should eq("8.0.47-0.5.0")
          boot.restarts.should eq(1)
          boot.canaries.should be_empty
          answer["key_scope"].should eq("unchecked")
        ensure
          FileUtils.rm_rf(cut)
        end
      end
    end

    it "rolls back current.json with the files when the record was never written" do
      with_host do |root, key, system, installer|
        # A move that passed and wrote current.json, then was cut off before
        # its record: its marker (as of the restart) is still there.
        cut = "#{root}-cut"
        system.on_restart = ->(n : Int32) { FileUtils.cp_r(root, cut) if n == 1; nil }
        install(installer, system, bundle(key))
        begin
          FileUtils.cp(cut + GatewayInstaller::MARKER, root + GatewayInstaller::MARKER)
          File.delete("#{root}/var/lib/gentility-gateway/moves/#{MOVE}.json")
          JSON.parse(File.read(root + GatewayInstaller::CURRENT))["bundle"].should eq("8.0.60-0.5.0")

          _, later = install(installer, system, bundle(key, plugin: "broken"), move: "019a5b2c-0000-7000-8000-000000000002")
          JSON.parse(File.read("#{root}/var/lib/gentility-gateway/moves/#{MOVE}.json"))["reason"].should eq("interrupted")
          later["previous"]["bundle"].should eq("8.0.47-0.1.0")
          JSON.parse(File.read(root + GatewayInstaller::CURRENT))["bundle"].should eq("8.0.47-0.1.0")
        ensure
          FileUtils.rm_rf(cut)
        end
      end
    end

    it "refuses the next move, saying why, when it cannot be put back" do
      with_host do |root, key, system, installer|
        system.on_restart = ->(n : Int32) { File.delete("#{root}/var/lib/gentility-gateway/previous/2") if n == 1 }
        install(installer, system, bundle(key, plugin: "broken"))
        status, answer = install(installer, system, bundle(key), move: "019a5b2c-0000-7000-8000-000000000002")
        status.should eq(1)
        answer["result"].should eq("refused")
        answer["reason"].as_s.should start_with("a cut-off move could not be put back, so this one was not tried")
      end
    end

    it "answers failed, keeping its marker, when the roll back cannot finish" do
      with_host do |root, key, system, installer|
        system.on_restart = ->(n : Int32) { File.delete("#{root}/var/lib/gentility-gateway/previous/2") if n == 1 }
        status, answer = install(installer, system, bundle(key, plugin: "broken"))
        status.should eq(1)
        answer["result"].should eq("failed")
        answer["running"].raw.should be_nil
        File.exists?(root + GatewayInstaller::MARKER).should be_true
        File.exists?("#{root}/var/lib/gentility-gateway/moves/#{MOVE}.json").should be_false
      end
    end
  end

  describe "a plugin-only move (the same upstream version)" do
    it "leaves the running proxy binary alone when its bytes match" do
      with_host do |root, key, system, installer|
        _, answer = install(installer, system, bundle(key, upstream: "8.0.47"))
        answer["result"].should eq("moved")
        File.exists?("#{root}/var/lib/gentility-gateway/previous/3").should be_false
        File.read(root + "/opt/cliproxyapi/8.0.47/cli-proxy-api").should eq("proxy 8.0.47")
      end
    end

    it "keeps and restores the proxy binary when its bytes differ" do
      with_host do |root, key, system, installer|
        _, answer = install(installer, system, bundle(key, upstream: "8.0.47", proxy: "rebuilt 8.0.47", plugin: "broken"))
        answer["result"].should eq("rolled_back")
        File.read(root + "/opt/cliproxyapi/8.0.47/cli-proxy-api").should eq("proxy 8.0.47")
      end
    end
  end

  describe "never follows a link the proxy's user could plant:" do
    it "a plugin that is a link is refused before the host changes" do
      with_host do |root, key, system, installer|
        outside = "#{root}/root-only"
        File.write(outside, "secret")
        plugin = "#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so"
        File.delete(plugin)
        File.symlink(outside, plugin)
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("refused")
        answer["reason"].as_s.should start_with("could not keep the previous version")
        File.read(outside).should eq("secret")
        File.symlink?(plugin).should be_true
        system.restarts.should eq(0)
      end
    end

    it "a plugin dir that is a link is refused" do
      with_host do |root, key, system, installer|
        outside = "#{root}/elsewhere"
        Dir.mkdir(outside)
        dir = "#{root}#{GatewayInstaller::PLUGIN_DIR}"
        FileUtils.mv(dir, "#{root}/moved-away")
        File.symlink(outside, dir)
        _, answer = install(installer, system, bundle(key))
        answer["result"].should eq("refused")
        Dir.children(outside).should be_empty
      end
    end

    it "a config.yaml swapped for a link mid-move is replaced, not written through" do
      with_host do |root, key, system, installer|
        outside = "#{root}/root-only"
        File.write(outside, "secret")
        config = root + GatewayInstaller::CONFIG
        system.on_restart = ->(n : Int32) { (File.delete(config); File.symlink(outside, config)) if n == 1; nil }
        _, answer = install(installer, system, bundle(key, plugin: "broken"))
        answer["result"].should eq("rolled_back")
        File.read(outside).should eq("secret")
        File.symlink?(config).should be_false
        File.read(config).should eq(CONFIG)
      end
    end
  end

  describe "refuses, leaving the host as it was," do
    {
      "a wrong sha256"                  => {->(k : Ed25519::SigningKey) { bundle(k) }, "0" * 64, "bundle sha256 differs from the request"},
      "a bad signature"                 => {->(k : Ed25519::SigningKey) { bundle(k, signing_key: Ed25519::SigningKey.new) }, nil, "bad signature"},
      "an unknown key id"               => {->(k : Ed25519::SigningKey) { bundle(k, sig_key_id: "00" * 8) }, nil, "unknown key id"},
      "the wrong kind"                  => {->(k : Ed25519::SigningKey) { bundle(k, kind: "desk-host") }, nil, "not a gateway bundle"},
      "an unknown format"               => {->(k : Ed25519::SigningKey) { bundle(k, format: 2) }, nil, "unknown manifest format"},
      "a file whose sha256 differs"     => {->(k : Ed25519::SigningKey) { bundle(k, shipped_plugin: "plugin 6.6.6") }, nil, "gentility-usage.so sha256 differs from the manifest"},
      "a bundle with a path in it"      => {->(k : Ed25519::SigningKey) { bundle(k, extra: [{"../escape", "x"}]) }, nil, "bundle holds a path"},
      "a bundle with a repeated member" => {->(k : Ed25519::SigningKey) { bundle(k, extra: [{"manifest.json", "{}"}]) }, nil, "bundle repeats manifest.json"},
    }.each do |what, (make, sha, reason)|
      it "#{what}" do
        with_host do |root, key, system, installer|
          bytes = make.call(key)
          status, answer = install(installer, system, bytes, sha || sha256(bytes))

          status.should eq(0)
          answer["result"].should eq("refused")
          answer["reason"].should eq(reason)
          answer["running"]["bundle"].should eq("8.0.47-0.1.0")
          host_unchanged(root, system)
          File.exists?("#{root}/var/lib/gentility-gateway/staging/#{MOVE}").should be_false
        end
      end
    end

    it "a bundle holding a directory" do
      with_host do |root, key, system, installer|
        bytes = TarWriter.build([{"sub", ""}], type: '5')
        _, answer = install(installer, system, bytes)
        answer["reason"].should eq("bundle holds a non-file entry")
        host_unchanged(root, system)
      end
    end

    it "a host whose drop-in names no proxy binary" do
      with_host do |root, key, system, installer|
        File.write(root + GatewayInstaller::DROP_IN, "[Service]\nExecStart=/usr/bin/other\n")
        _, answer = install(installer, system, bundle(key))
        answer["reason"].should eq("the drop-in names no proxy binary")
        system.fetches.should eq(0)
        system.restarts.should eq(0)
      end
    end
  end

  describe "rejects bad arguments before touching the host:" do
    sha = "a" * 64
    {
      "none"                => [] of String,
      "an extra argument"   => [MOVE, URL, sha, "/tmp/keys.json"],
      "a path as move id"   => ["../../etc/passwd", URL, sha],
      "a move id with /"    => ["019a5b2c-0000-7000-8000-00000000000/", URL, sha],
      "another host's URL"  => [MOVE, "https://example.com/gateway-8.0.60-0.2.0/bundle.tar", sha],
      "a plain-http URL"    => [MOVE, URL.sub("https", "http"), sha],
      "a file URL"          => [MOVE, "file:///tmp/bundle.tar", sha],
      "a URL with ../"      => [MOVE, URL.sub("gateway-8.0.60-0.2.0", "gateway-8/../../x"), sha],
      "a short sha256"      => [MOVE, URL, "abc"],
      "an uppercase sha256" => [MOVE, URL, "A" * 64],
      "a path as sha256"    => [MOVE, URL, "/etc/gentility-gateway/keys.json"],
    }.each do |what, args|
      it what do
        with_host do |root, key, system, installer|
          status, output = installer.run(args)
          status.should eq(2)
          JSON.parse(output)["result"].should eq("refused")
          JSON.parse(output)["reason"].should eq("bad arguments")
          system.fetches.should eq(0)
          Dir.exists?("#{root}/var/lib/gentility-gateway/moves").should be_false
        end
      end
    end
  end
end

describe GatewayInstaller::HostSystem do
  describe "#canary" do
    it "asks one chat completion as the key, and answers the status and up to 64 KiB of the body" do
      asked = [] of String
      server = HTTP::Server.new do |context|
        request = context.request
        asked << "#{request.method} #{request.path} #{request.headers["Authorization"]} #{request.headers["Content-Type"]} #{request.body.try(&.gets_to_end)}"
        context.response.status_code = 403
        context.response.print "x" * 200_000
      end
      address = server.bind_tcp("127.0.0.1", 0)
      spawn { server.listen }
      begin
        status, body = GatewayInstaller::HostSystem.new.canary("http://127.0.0.1:#{address.port}/v1/chat/completions", "k_1", "gw/m").not_nil!
        status.should eq(403)
        body.size.should eq(64 * 1024)
        asked.should eq([%(POST /v1/chat/completions Bearer k_1 application/json {"model":"gw/m","max_tokens":1,"messages":[{"role":"user","content":"x"}]})])
      ensure
        server.close
      end
    end

    it "gives nil at its bound when the proxy trickles its answer" do
      server = HTTP::Server.new do |context|
        30.times { context.response.print "x"; context.response.flush; sleep 100.milliseconds }
      end
      address = server.bind_tcp("127.0.0.1", 0)
      spawn { server.listen }
      begin
        started = Time.instant
        GatewayInstaller::HostSystem.new(canary_within: 500.milliseconds)
          .canary("http://127.0.0.1:#{address.port}/v1/chat/completions", "k", "m").should be_nil
        (Time.instant - started).should be < 1.5.seconds
      ensure
        server.close
      end
    end

    it "gives nil when nothing listens" do
      closed = TCPServer.new("127.0.0.1", 0)
      port = closed.local_address.port
      closed.close
      GatewayInstaller::HostSystem.new.canary("http://127.0.0.1:#{port}/v1/chat/completions", "k", "m").should be_nil
    end
  end

  it "knows its own addresses from another host's" do
    host = GatewayInstaller::HostSystem.new
    host.local?(Socket::IPAddress.new("127.0.0.1", 8317)).should be_true
    host.local?(Socket::IPAddress.new("192.0.2.1", 8317)).should be_false
  end
end

describe "the Ed25519 verifier" do
  # RFC 8032 section 7.1, test 1: proof the library agrees with the standard,
  # not only with its own signer.
  it "accepts the RFC 8032 test vector and nothing else" do
    public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".hexbytes
    signature = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" \
                 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").hexbytes
    Ed25519.verify(signature, Bytes.empty, public_key).should be_true
    Ed25519.verify(signature, "x".to_slice, public_key).should be_false
  end
end
