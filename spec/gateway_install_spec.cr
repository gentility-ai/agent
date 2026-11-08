require "spec"
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

# A host whose cliproxyapi "runs" whatever plugin is installed at restart: a
# plugin file reading "plugin <version>" registers, anything else does not.
class FakeSystem < GatewayInstaller::System
  getter fetches = 0
  getter restarts = 0
  getter clock = Time.utc(2026, 11, 8)
  property bundles = {} of String => Bytes
  @journal = ""

  def initialize(@root : String)
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
    plugin = File.read("#{@root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so")
    @journal = if version = plugin.lchop?("plugin ")
                 "plugin registered plugin_id=gentility-usage name=usage version=#{version}\n" \
                 "API server started successfully on: [::1]:8317\n"
               else
                 "plugin load failed\nAPI server started successfully on: [::1]:8317\n"
               end
    true
  end

  def journal_since(since : Time) : String
    @journal
  end

  def models_status(url : String) : Int32?
    url == "http://[::1]:8317/v1/models" ? 401 : nil
  end

  def now : Time
    @clock
  end

  def sleep(span : Time::Span) : Nil
    @clock += span
  end
end

MOVE   = "019a5b2c-0000-7000-8000-000000000001"
URL    = "https://github.com/gentility-ai/gateway/releases/download/gateway-8.0.60-0.2.0/bundle.tar"
DROPIN = "[Service]\nExecStart=\nExecStart=/opt/cliproxyapi/8.0.47/cli-proxy-api -config /var/lib/cliproxyapi/config.yaml\n"

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
           plugin = "plugin 0.2.0",
           kind = "gateway",
           format = 1,
           signing_key = key,
           sig_key_id = key_id(key),
           shipped_plugin : String? = nil,
           extra = [] of {String, String}) : Bytes
  archive = String.new(gzip([{"cli-proxy-api", "proxy 8.0.60"}, {"LICENSE", "MIT"}]))
  manifest = {
    "kind"     => kind,
    "format"   => format,
    "bundle"   => "8.0.60-0.2.0",
    "upstream" => {"repo" => "router-for-me/CLIProxyAPI", "version" => "8.0.60",
                   "archive" => "CLIProxyAPI_8.0.60_linux_amd64.tar.gz", "sha256" => sha256(archive)},
    "plugin" => {"id" => "gentility-usage", "version" => "0.2.0", "commit" => "abc",
                 "file" => "gentility-usage.so", "sha256" => sha256(plugin)},
    "unknown_field" => "ignored",
  }.to_json
  sig = {"key_id" => sig_key_id, "signature" => Base64.strict_encode(signing_key.sign(manifest))}.to_json
  TarWriter.build([
    {"manifest.json", manifest},
    {"manifest.sig", sig},
    {"CLIProxyAPI_8.0.60_linux_amd64.tar.gz", archive},
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
    GatewayInstaller::CONFIG                             => "host: \"::1\"\nport: 8317\n",
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
      answer["running"].should eq(JSON.parse(%({"bundle":"8.0.60-0.2.0","upstream_version":"8.0.60","plugin_version":"0.2.0"})))
      answer["previous"]["bundle"].should eq("8.0.47-0.1.0")

      File.read(root + GatewayInstaller::DROP_IN).should contain("ExecStart=/opt/cliproxyapi/8.0.60/cli-proxy-api -config")
      File.read(root + "/opt/cliproxyapi/8.0.60/cli-proxy-api").should eq("proxy 8.0.60")
      File.read(root + "/opt/cliproxyapi/8.0.47/cli-proxy-api").should eq("proxy 8.0.47")
      File.read("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so").should eq("plugin 0.2.0")
      File.read("#{root}/var/lib/gentility-gateway/previous/gentility-usage.so").should eq("plugin 0.1.0")
      JSON.parse(File.read(root + GatewayInstaller::CURRENT)).should eq(answer["running"])
      JSON.parse(File.read("#{root}/var/lib/gentility-gateway/moves/#{MOVE}.json")).should eq(answer)
      File.exists?("#{root}/var/lib/gentility-gateway/staging/#{MOVE}").should be_false
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
      answer["reason"].as_s.should start_with("plugin gentility-usage 0.2.0 did not register")
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
      (system.clock - Time.utc(2026, 11, 8)).should eq(60.seconds)
    end
  end

  it "says so when the previous version fails its check too" do
    with_host do |root, key, system, installer|
      File.write("#{root}#{GatewayInstaller::PLUGIN_DIR}/gentility-usage.so", "broken before")
      _, answer = install(installer, system, bundle(key, plugin: "broken"))
      answer["result"].should eq("rolled_back")
      answer["reason"].as_s.should contain("the previous version failed its check too")
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
