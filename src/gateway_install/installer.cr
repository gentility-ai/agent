# The root helper that installs a signed gateway bundle on a gateway host and
# puts the previous version back when the new one fails its check. The steps
# are those of the gateway bundle contract ("The helper"), numbered as there.
#
# It takes three words from the caller — a move id, the bundle's release URL
# and its sha256 — and no paths: every path below is fixed, and the keys it
# trusts are its own root-owned set.

require "json"
require "yaml"
require "uri"
require "http/client"
require "digest/sha256"
require "base64"
require "file_utils"
require "compress/gzip"
require "ed25519"

module GatewayInstaller
  MOVE_ID    = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
  SHA256     = /\A[0-9a-f]{64}\z/
  BUNDLE_URL = %r{\Ahttps://github\.com/gentility-ai/gateway/releases/download/gateway-[0-9][0-9A-Za-z.-]*/bundle\.tar\z}
  # A version or file name from the manifest: never a path.
  WORD       = /\A[0-9A-Za-z][0-9A-Za-z._+-]*\z/
  PROXY_PATH = %r{/opt/cliproxyapi/[^/\s]+/cli-proxy-api}

  KEYS       = "/etc/gentility-gateway/keys.json"
  STATE      = "/var/lib/gentility-gateway"
  CURRENT    = "#{STATE}/current.json"
  DROP_IN    = "/etc/systemd/system/cliproxyapi.service.d/omp-gateway.conf"
  CONFIG     = "/var/lib/cliproxyapi/config.yaml"
  PLUGIN_DIR = "/var/lib/cliproxyapi/plugins/linux/amd64"
  UNIT       = "cliproxyapi"

  class Refused < Exception
  end

  record Running, bundle : String, upstream_version : String, plugin_version : String do
    include JSON::Serializable
  end

  @[JSON::Serializable::Options(emit_nulls: true)]
  struct Answer
    include JSON::Serializable

    getter move_id : String?
    getter result : String
    getter reason : String
    getter running : Running?
    getter previous : Running?

    def initialize(@move_id, @result, @reason, @running, @previous)
    end
  end

  record Manifest,
    bundle : String,
    upstream_version : String,
    archive : String,
    archive_sha256 : String,
    plugin_id : String,
    plugin_version : String,
    plugin_file : String,
    plugin_sha256 : String do
    def running : Running
      Running.new(bundle, upstream_version, plugin_version)
    end

    def proxy : String
      "/opt/cliproxyapi/#{upstream_version}/cli-proxy-api"
    end

    def plugin : String
      "#{PLUGIN_DIR}/#{plugin_file}"
    end
  end

  # Reads a ustar or GNU tar stream, yielding each entry's name, type flag and
  # contents. Pax headers are skipped; the caller judges every other entry.
  module Tar
    def self.each(io : IO, & : String, Char, IO ->) : Nil
      header = Bytes.new(512)
      while io.read_fully?(header) && !header.all?(&.zero?)
        size = String.new(header[124, 12]).delete("\0 ").to_i64(8)
        type = header[156].unsafe_chr
        name = field(header, 0, 100)
        if String.new(header[257, 5]) == "ustar" && !(prefix = field(header, 345, 155)).empty?
          name = "#{prefix}/#{name}"
        end
        body = IO::Sized.new(io, size)
        yield name, type, body unless type.in?('x', 'g')
        body.skip_to_end
        io.skip((512 - size % 512) % 512)
      end
    end

    private def self.field(header : Bytes, start : Int32, length : Int32) : String
      String.new(header[start, length]).split('\0', 2).first
    end

    def self.regular?(type : Char) : Bool
      type.in?('0', '\0')
    end
  end

  # What the helper asks of the host, behind a seam so tests run without root.
  abstract class System
    abstract def fetch(url : String, dest : String) : Nil
    abstract def daemon_reload : Bool
    abstract def restart : Bool
    abstract def journal_since(since : Time) : String
    abstract def models_status(url : String) : Int32?

    def now : Time
      Time.utc
    end

    def sleep(span : Time::Span) : Nil
      ::sleep(span)
    end
  end

  class HostSystem < System
    MAX_BUNDLE = 512_i64 * 1024 * 1024

    def fetch(url : String, dest : String, redirects = 5) : Nil
      uri = URI.parse(url)
      raise Refused.new("bundle URL is not https") unless uri.scheme == "https"
      client = HTTP::Client.new(uri)
      client.connect_timeout = 30.seconds
      client.read_timeout = 60.seconds
      location = client.get(uri.request_target) do |response|
        next response.headers["Location"]? if response.status.redirection?
        raise Refused.new("fetch answered #{response.status_code}") unless response.status.success?
        File.open(dest, "w") { |file| IO.copy(response.body_io, file, MAX_BUNDLE + 1) }
        raise Refused.new("bundle is too large") if File.size(dest) > MAX_BUNDLE
        nil
      end
      client.close
      return unless location
      raise Refused.new("fetch redirected too often") if redirects == 0
      fetch(uri.resolve(location).to_s, dest, redirects - 1)
    end

    def daemon_reload : Bool
      Process.run("/usr/bin/systemctl", ["daemon-reload"]).success?
    end

    def restart : Bool
      Process.run("/usr/bin/systemctl", ["restart", UNIT]).success?
    end

    def journal_since(since : Time) : String
      output = IO::Memory.new
      Process.run("/usr/bin/journalctl",
        ["-u", UNIT, "--since", "@#{since.to_unix}", "-o", "cat", "--no-pager"],
        output: output)
      output.to_s
    end

    def models_status(url : String) : Int32?
      uri = URI.parse(url)
      client = HTTP::Client.new(uri)
      client.connect_timeout = 5.seconds
      client.read_timeout = 5.seconds
      client.get(uri.request_target).status_code
    rescue IO::Error | Socket::Error
      nil
    ensure
      client.try &.close
    end
  end

  class Installer
    def initialize(@system : System, @root = "", @check_within = 60.seconds, @poll_every = 2.seconds)
    end

    # Answers with an exit status and the answer's JSON.
    def run(args : Array(String)) : {Int32, String}
      unless args.size == 3 && args[0].matches?(MOVE_ID) && args[1].matches?(BUNDLE_URL) && args[2].matches?(SHA256)
        return {2, Answer.new(nil, "refused", "bad arguments", current, current).to_json}
      end
      move_id, url, sha256 = args

      prepare_dirs
      File.open(at("#{STATE}/lock"), "w") do |lock|
        lock.flock_exclusive
        # 1. Repeat move.
        record = at("#{STATE}/moves/#{move_id}.json")
        return {0, File.read(record)} if File.exists?(record)

        answer = attempt(move_id, url, sha256)
        # 8. Record.
        write_atomic(record, answer.to_json)
        FileUtils.rm_rf(staging(move_id))
        {0, answer.to_json}
      end
    end

    def current : Running?
      Running.from_json(File.read(at(CURRENT))) if File.exists?(at(CURRENT))
    rescue JSON::ParseException | JSON::SerializableError
      nil
    end

    private def attempt(move_id : String, url : String, sha256 : String) : Answer
      previous = current
      manifest = begin
        fetch_and_verify(url, sha256, staging(move_id))
      rescue ex : Refused
        return Answer.new(move_id, "refused", ex.message.to_s, previous, previous)
      rescue ex
        return Answer.new(move_id, "refused", "bundle unreadable: #{ex.message}", previous, previous)
      end

      # 4. Install beside, and 5. switch: the drop-in changes in one rename.
      kept = [] of {String, String?}
      begin
        keep_previous(manifest, kept)
        install_beside(manifest, staging(move_id))
        write_atomic(at(DROP_IN), File.read(at(DROP_IN)).gsub(PROXY_PATH, manifest.proxy))
      rescue ex
        restore(kept)
        return Answer.new(move_id, "rolled_back", "install failed: #{ex.message}", previous, previous)
      end

      # 6. Check.
      reason = restart_and_check(manifest.plugin_id, manifest.plugin_version)
      if reason.nil?
        write_atomic(at(CURRENT), manifest.running.to_json)
        return Answer.new(move_id, "moved", "", manifest.running, previous)
      end

      # 7. Roll back.
      restore(kept)
      if again = restart_and_check(manifest.plugin_id, previous.try(&.plugin_version))
        reason = "#{reason}; the previous version failed its check too: #{again}"
      end
      Answer.new(move_id, "rolled_back", reason, previous, previous)
    end

    # 2. Fetch, and 3. verify — the copy in the staging dir, never the caller's.
    private def fetch_and_verify(url : String, sha256 : String, dir : String) : Manifest
      FileUtils.rm_rf(dir)
      Dir.mkdir(dir, 0o700)
      File.chmod(dir, 0o700)
      tar = File.join(dir, "bundle.tar")
      @system.fetch(url, tar)
      raise Refused.new("bundle sha256 differs from the request") unless sha256_of(tar) == sha256

      files = File.join(dir, "bundle")
      extract_flat(tar, files)
      manifest_json = read_member(files, "manifest.json")
      verify_signature(manifest_json, read_member(files, "manifest.sig"))

      json = JSON.parse(manifest_json)
      raise Refused.new("not a gateway bundle") unless json["kind"]?.try(&.as_s?) == "gateway"
      raise Refused.new("unknown manifest format") unless json["format"]?.try(&.as_i64?) == 1
      manifest = Manifest.new(
        bundle: json["bundle"].as_s,
        upstream_version: json["upstream"]["version"].as_s,
        archive: json["upstream"]["archive"].as_s,
        archive_sha256: json["upstream"]["sha256"].as_s,
        plugin_id: json["plugin"]["id"].as_s,
        plugin_version: json["plugin"]["version"].as_s,
        plugin_file: json["plugin"]["file"].as_s,
        plugin_sha256: json["plugin"]["sha256"].as_s)
      words = {manifest.bundle, manifest.upstream_version, manifest.archive,
               manifest.plugin_id, manifest.plugin_version, manifest.plugin_file}
      raise Refused.new("manifest names a path") unless words.all?(&.matches?(WORD))

      {manifest.archive => manifest.archive_sha256, manifest.plugin_file => manifest.plugin_sha256}.each do |name, digest|
        path = File.join(files, name)
        raise Refused.new("bundle lacks #{name}") unless File.file?(path)
        raise Refused.new("#{name} sha256 differs from the manifest") unless sha256_of(path) == digest
      end

      unless File.exists?(at(DROP_IN)) && File.read(at(DROP_IN)).matches?(PROXY_PATH)
        raise Refused.new("the drop-in names no proxy binary")
      end
      manifest
    end

    private def extract_flat(tar : String, dir : String) : Nil
      Dir.mkdir(dir, 0o700)
      File.open(tar) do |io|
        Tar.each(io) do |name, type, body|
          raise Refused.new("bundle holds a non-file entry") unless Tar.regular?(type)
          raise Refused.new("bundle holds a path") unless name.matches?(WORD)
          path = File.join(dir, name)
          raise Refused.new("bundle repeats #{name}") if File.exists?(path)
          File.write(path, body)
        end
      end
    end

    private def read_member(dir : String, name : String) : String
      path = File.join(dir, name)
      raise Refused.new("bundle lacks #{name}") unless File.file?(path)
      File.read(path)
    end

    private def verify_signature(manifest_json : String, sig_json : String) : Nil
      keys = begin
        JSON.parse(File.read(at(KEYS)))["keys"].as_h
      rescue
        raise Refused.new("no pinned keys")
      end
      sig = JSON.parse(sig_json)
      key = keys[sig["key_id"].as_s]? || raise Refused.new("unknown key id")
      signature = Base64.decode(sig["signature"].as_s)
      verified = Ed25519.verify(signature, manifest_json.to_slice, Base64.decode(key.as_s)) rescue false
      raise Refused.new("bad signature") unless verified
    end

    # Keeps the drop-in, config and running plugin under previous/, noting each
    # one as it is kept so a restore never touches what was not.
    private def keep_previous(manifest : Manifest, kept : Array({String, String?})) : Nil
      previous = at("#{STATE}/previous")
      FileUtils.rm_rf(previous)
      Dir.mkdir(previous, 0o700)
      File.chmod(previous, 0o700)
      {DROP_IN, CONFIG, manifest.plugin}.each do |path|
        target = at(path)
        if File.exists?(target)
          copy = File.join(previous, File.basename(path))
          copy_as(target, copy)
          kept << {target, copy}
        else
          kept << {target, nil}
        end
      end
    end

    private def install_beside(manifest : Manifest, dir : String) : Nil
      files = File.join(dir, "bundle")
      proxy = at(manifest.proxy)
      Dir.mkdir_p(File.dirname(proxy))
      found = false
      File.open(File.join(files, manifest.archive)) do |archive|
        Compress::Gzip::Reader.open(archive) do |gzip|
          Tar.each(gzip) do |name, type, body|
            next unless Tar.regular?(type) && name.lchop("./") == "cli-proxy-api"
            write_atomic(proxy, body, 0o755)
            found = true
          end
        end
      end
      raise "upstream archive lacks cli-proxy-api" unless found

      plugin = at(manifest.plugin)
      Dir.mkdir_p(File.dirname(plugin))
      source = File.join(files, manifest.plugin_file)
      copy_as(source, plugin, like: File.exists?(plugin) ? plugin : source)
    end

    private def restore(kept : Array({String, String?})) : Nil
      kept.each do |target, copy|
        if copy
          copy_as(copy, target)
        else
          File.delete?(target)
        end
      end
    end

    private def restart_and_check(plugin_id : String, version : String?) : String?
      return "daemon-reload failed" unless @system.daemon_reload
      since = @system.now
      @system.restart
      check(plugin_id, version, since)
    end

    # 6. Check, until it passes or the time is up.
    private def check(plugin_id : String, version : String?, since : Time) : String?
      deadline = @system.now + @check_within
      loop do
        reason = check_once(plugin_id, version, since)
        return reason if reason.nil? || @system.now >= deadline
        @system.sleep(@poll_every)
      end
    end

    private def check_once(plugin_id : String, version : String?, since : Time) : String?
      journal = @system.journal_since(since)
      unless journal.each_line.any? { |line| registered?(line, plugin_id, version) }
        return "plugin #{plugin_id} #{version} did not register".squeeze(' ')
      end
      return "the API server did not start" unless journal.includes?("API server started successfully")
      url = models_url
      return "config.yaml is unreadable" unless url
      status = @system.models_status(url)
      return "/v1/models answered #{status || "nothing"}" unless {200, 401}.includes?(status)
      nil
    end

    private def registered?(line : String, plugin_id : String, version : String?) : Bool
      line.includes?("plugin registered") &&
        token?(line, "plugin_id", plugin_id) &&
        (version.nil? || token?(line, "version", version))
    end

    private def token?(line : String, key : String, value : String) : Bool
      line.matches?(/(^|\s)#{key}="?#{Regex.escape(value)}"?(\s|$)/)
    end

    private def models_url : String?
      config = YAML.parse(File.read(at(CONFIG)))
      host = config["host"]?.try(&.as_s?).presence || "127.0.0.1"
      port = config["port"]?.try(&.as_i?) || 8317
      host = "[#{host}]" if host.includes?(':')
      "http://#{host}:#{port}/v1/models"
    rescue File::NotFoundError | YAML::ParseException
      nil
    end

    private def prepare_dirs : Nil
      {STATE => 0o755, "#{STATE}/moves" => 0o755, "#{STATE}/staging" => 0o700}.each do |dir, mode|
        Dir.mkdir_p(at(dir))
        File.chmod(at(dir), mode)
      end
    end

    # Copies a file with the owner and mode of `like`, through a rename, so the
    # target is never half written.
    private def copy_as(from : String, to : String, like : String = from) : Nil
      info = File.info(like)
      temp = "#{to}.gateway-new"
      File.copy(from, temp)
      File.chown(temp, info.owner_id.to_i, info.group_id.to_i)
      File.chmod(temp, info.permissions)
      File.rename(temp, to)
    end

    private def write_atomic(path : String, content : String | IO, mode = 0o644) : Nil
      temp = "#{path}.gateway-new"
      File.write(temp, content)
      File.chmod(temp, mode)
      File.rename(temp, path)
    end

    private def staging(move_id : String) : String
      at("#{STATE}/staging/#{move_id}")
    end

    private def sha256_of(path : String) : String
      Digest::SHA256.new.file(path).hexfinal
    end

    private def at(path : String) : String
      @root + path
    end
  end
end
