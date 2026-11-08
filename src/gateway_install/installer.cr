# The root helper that installs a signed gateway bundle on a gateway host and
# puts the previous version back when the new one fails its check. The steps
# are those of the gateway bundle contract ("The helper"), numbered as there.
#
# It takes three words from the caller — a move id, the bundle's release URL
# and its sha256 — and no paths: every path below is fixed, and the keys it
# trusts are its own root-owned set. It moves in a systemd unit of its own, so
# an agent restart cannot cut it off, and it reaches the host's files through
# Tree, which never follows a link the proxy's user could have planted.

require "json"
require "yaml"
require "uri"
require "http/client"
require "digest/sha256"
require "base64"
require "file_utils"
require "compress/gzip"
require "ed25519"
require "./tree"

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
  MARKER     = "#{STATE}/in-flight.json"
  DROP_IN    = "/etc/systemd/system/cliproxyapi.service.d/omp-gateway.conf"
  CONFIG     = "/var/lib/cliproxyapi/config.yaml"
  PLUGIN_DIR = "/var/lib/cliproxyapi/plugins/linux/amd64"
  UNIT       = "cliproxyapi"
  CONFIG_MAX = 1024_i64 * 1024
  # The boot unit's word: put back what a cut-off move left, before the proxy starts.
  RECOVER = "--recover"
  WATCHER = "file watcher started for config and auth directory changes"

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

  # Written before the host changes and removed once the move is recorded: a
  # helper that finds one knows a move was cut off, and puts back what it kept.
  record Marker, move_id : String, plugin_id : String, previous : Running?, kept : Array({String, String?}) do
    include JSON::Serializable
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
        if String.new(header[257, 6]) == "ustar\0" && !(prefix = field(header, 345, 155)).empty?
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

  # Where the helper runs: in its move's own unit, outside any unit (from the
  # agent, through sudo), or somewhere it cannot tell.
  enum Placement
    Isolated
    Outside
    Unknown
  end

  # What the helper asks of the host, behind a seam so tests run without root.
  abstract class System
    STARTED = Time.instant

    abstract def placement(move_id : String) : Placement
    abstract def isolate(args : Array(String)) : {Int32, String}
    abstract def fetch(url : String, dest : String) : Nil
    abstract def daemon_reload : Bool
    abstract def restart : Bool
    abstract def unit_state : {Int64, Int64}?
    abstract def exe(pid : Int64) : String?
    abstract def journal_since(since : Time) : String
    abstract def models_status(url : String) : Int32?

    def now : Time
      Time.utc
    end

    # A monotonic clock, for deadlines.
    def ticks : Time::Span
      Time.instant - STARTED
    end

    def sleep(span : Time::Span) : Nil
      ::sleep(span)
    end
  end

  class HostSystem < System
    SELF         = "/usr/libexec/gentility/gentility-gateway-install"
    MOVE_UNIT    = "gentility-gateway-move-"
    MAX_BUNDLE   = 512_i64 * 1024 * 1024
    FETCH_WITHIN = 10.minutes

    # Isolated in its move's own unit, which systemd made, and not in the
    # agent's service, whose restart would kill it midway. Without a cgroup v2
    # line it cannot tell; inside some other unit (sudo strips INVOCATION_ID,
    # so not the agent's), another systemd-run would only nest.
    def placement(move_id : String) : Placement
      line = File.read("/proc/self/cgroup").lines.find(&.starts_with?("0::"))
      return Placement::Unknown unless line
      return Placement::Isolated if line.matches?(%r{\A0::/system\.slice/#{MOVE_UNIT}#{move_id}-[0-9a-f]{8}\.service\z})
      ENV["INVOCATION_ID"]? ? Placement::Unknown : Placement::Outside
    rescue File::Error
      Placement::Unknown
    end

    # Runs the move again in a unit of its own. Killing this process (the
    # agent restarting) leaves that unit running.
    def isolate(args : Array(String)) : {Int32, String}
      output = IO::Memory.new
      status = Process.run("/usr/bin/systemd-run",
        ["--wait", "--pipe", "--collect", "--quiet", "--unit=#{MOVE_UNIT}#{args[0]}-#{Random::Secure.hex(4)}", SELF] + args,
        output: output, error: Process::Redirect::Inherit)
      {status.exit_code? || 1, output.to_s}
    end

    def fetch(url : String, dest : String) : Nil
      File.open(dest, "w") { |file| get(url, file, Time.instant + FETCH_WITHIN, 5) }
    end

    private def get(url : String, file : File, deadline : Time::Instant, redirects : Int32) : Nil
      uri = URI.parse(url)
      raise Refused.new("bundle URL is not https") unless uri.scheme == "https"
      client = HTTP::Client.new(uri)
      client.connect_timeout = 30.seconds
      client.read_timeout = 60.seconds
      location = client.get(uri.request_target) do |response|
        next response.headers["Location"]? if response.status.redirection?
        raise Refused.new("fetch answered #{response.status_code}") unless response.status.success?
        buffer = Bytes.new(64 * 1024)
        total = 0_i64
        while (read = response.body_io.read(buffer)) > 0
          total += read
          raise Refused.new("bundle is too large") if total > MAX_BUNDLE
          raise Refused.new("fetch took longer than #{FETCH_WITHIN.total_minutes.to_i} minutes") if Time.instant > deadline
          file.write(buffer[0, read])
        end
        nil
      end
      client.close
      return unless location
      raise Refused.new("fetch redirected too often") if redirects == 0
      get(uri.resolve(location).to_s, file, deadline, redirects - 1)
    end

    def daemon_reload : Bool
      Process.run("/usr/bin/systemctl", ["daemon-reload"]).success?
    end

    def restart : Bool
      Process.run("/usr/bin/systemctl", ["restart", UNIT]).success?
    end

    # The unit's MainPID and NRestarts.
    def unit_state : {Int64, Int64}?
      output = IO::Memory.new
      Process.run("/usr/bin/systemctl", ["show", UNIT, "--property=MainPID,NRestarts"], output: output)
      values = output.to_s.lines.to_h { |line| key, _, value = line.partition('='); {key, value} }
      {values["MainPID"].to_i64, values["NRestarts"].to_i64}
    rescue KeyError | ArgumentError
      nil
    end

    def exe(pid : Int64) : String?
      File.readlink("/proc/#{pid}/exe")
    rescue File::Error
      nil
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
    def initialize(@system : System, @root = "", @check_within = 60.seconds, @poll_every = 2.seconds, @settle = 15.seconds)
      @tree = Tree.new(@root)
    end

    # Answers with an exit status and the answer's JSON.
    def run(args : Array(String)) : {Int32, String}
      return {0, with_lock { recover(at_boot: true).try(&.to_json) || "" }} if args == [RECOVER]
      unless args.size == 3 && args[0].matches?(MOVE_ID) && args[1].matches?(BUNDLE_URL) && args[2].matches?(SHA256)
        return {2, Answer.new(nil, "refused", "bad arguments", current, current).to_json}
      end
      move_id, url, sha256 = args
      case @system.placement(move_id)
      in .outside?
        return isolate(args)
      in .unknown?
        return {1, Answer.new(move_id, "refused", "cannot tell whether the helper runs in a unit of its own", current, current).to_json}
      in .isolated?
      end

      with_lock do
        begin
          recover
        rescue ex
          reason = "a cut-off move could not be put back, so this one was not tried: #{ex.message}"
          return {1, Answer.new(move_id, "refused", reason, nil, current).to_json}
        end
        begin
          # 1. Repeat move.
          if record = @tree.read(record_path(move_id))
            return {0, record}
          end
          answer = attempt(move_id, url, sha256)
          finish(move_id, answer)
          {0, answer.to_json}
        rescue ex
          reason = "#{ex.message}; the next helper run puts the previous version back"
          {1, Answer.new(move_id, "failed", reason, nil, current).to_json}
        end
      end
    end

    def current : Running?
      Running.from_json(File.read(at(CURRENT))) if File.exists?(at(CURRENT))
    rescue JSON::ParseException | JSON::SerializableError
      nil
    end

    private def with_lock(&)
      prepare_dirs
      File.open(at("#{STATE}/lock"), "w") do |lock|
        lock.flock_exclusive
        yield
      end
    end

    private def isolate(args : Array(String)) : {Int32, String}
      @system.isolate(args)
    rescue ex
      {1, Answer.new(args[0], "refused", "could not start the move unit: #{ex.message}", current, current).to_json}
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

      kept = [] of {String, String?}
      begin
        keep_previous(manifest, staging(move_id), kept)
        @tree.write(MARKER, Marker.new(move_id, manifest.plugin_id, previous, kept).to_json, Owner.root(0o600))
      rescue ex
        return Answer.new(move_id, "refused", "could not keep the previous version: #{ex.message}", previous, previous)
      end

      # 4. Install beside, 5. switch, and 6. check. The drop-in changes in one
      # rename; the plugin, replaced in place before it, is the marker's to undo.
      reason = begin
        install_beside(manifest, staging(move_id), kept)
        switch(manifest)
        restart_and_check(manifest.plugin_id, manifest.plugin_version)
      rescue ex
        "install failed: #{ex.message}"
      end
      return Answer.new(move_id, "moved", "", manifest.running, previous) unless reason

      # 7. Roll back.
      roll_back(move_id, kept, manifest.plugin_id, previous, reason)
    end

    # Puts back what was kept and checks the previous version. When that fails
    # too, nothing known runs: the answer's `running` is null. Without
    # `restart`, the proxy is not running (boot): systemd starts it later.
    private def roll_back(move_id : String, kept : Array({String, String?}), plugin_id : String,
                          previous : Running?, reason : String, restart = true) : Answer
      kept.each do |target, copy|
        if copy
          raise "the kept copy of #{target} is gone" unless @tree.copy(copy, target)
        else
          @tree.delete(target)
        end
      end
      unless restart
        return Answer.new(move_id, "rolled_back", reason, previous, previous) if @system.daemon_reload
        return Answer.new(move_id, "rolled_back", "#{reason}; daemon-reload failed", nil, previous)
      end
      if again = restart_and_check(plugin_id, previous.try(&.plugin_version))
        return Answer.new(move_id, "rolled_back", "#{reason}; the previous version failed its check too: #{again}", nil, previous)
      end
      Answer.new(move_id, "rolled_back", reason, previous, previous)
    end

    # A move cut off midway (a crash, a reboot) left its marker: put the
    # previous version back and record the move as interrupted. At boot the
    # proxy has not started unless something started it by hand.
    private def recover(at_boot = false) : Answer?
      return unless json = @tree.read(MARKER)
      marker = Marker.from_json(json)
      unless @tree.exists?(record_path(marker.move_id))
        restart = !at_boot || (@system.unit_state.try(&.first) || 0) > 0
        answer = roll_back(marker.move_id, marker.kept, marker.plugin_id, marker.previous, "interrupted", restart)
      end
      finish(marker.move_id, answer)
      answer
    end

    # 8. Record: what runs, then the answer. A move cut off between the two
    # is rolled back by the next run, which writes both again.
    private def finish(move_id : String, answer : Answer?) : Nil
      if answer && answer.result != "refused"
        if running = answer.running
          @tree.write(CURRENT, running.to_json, Owner.root(0o644))
        else
          @tree.delete(CURRENT)
        end
      end
      @tree.write(record_path(move_id), answer.to_json, Owner.root(0o644)) if answer
      @tree.delete(MARKER)
      FileUtils.rm_rf(staging(move_id))
    end

    # 2. Fetch, and 3. verify — the copy in the staging dir, never the caller's.
    private def fetch_and_verify(url : String, sha256 : String, dir : String) : Manifest
      unless @tree.read(DROP_IN).try(&.matches?(PROXY_PATH))
        raise Refused.new("the drop-in names no proxy binary")
      end
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
      extract_proxy(File.join(files, manifest.archive), File.join(dir, "cli-proxy-api"))
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

    private def extract_proxy(archive : String, dest : String) : Nil
      found = false
      File.open(archive) do |file|
        Compress::Gzip::Reader.open(file) do |gzip|
          Tar.each(gzip) do |name, type, body|
            next unless Tar.regular?(type) && name.lchop("./") == "cli-proxy-api"
            raise Refused.new("upstream archive repeats cli-proxy-api") if found
            File.write(dest, body)
            found = true
          end
        end
      end
      raise Refused.new("upstream archive lacks cli-proxy-api") unless found
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

    # Keeps under previous/ what the move will change, noting each path as it
    # goes (nil when there was no file) so a roll back touches nothing else.
    # The proxy is kept only when the move overwrites it with different bytes.
    private def keep_previous(manifest : Manifest, dir : String, kept : Array({String, String?})) : Nil
      previous = at("#{STATE}/previous")
      FileUtils.rm_rf(previous)
      Dir.mkdir(previous, 0o700)
      File.chmod(previous, 0o700)
      staged = sha256_of(File.join(dir, "cli-proxy-api"))
      paths = [DROP_IN, CONFIG, manifest.plugin]
      paths << manifest.proxy unless @tree.read(manifest.proxy) { |io, _| io && sha256_of(io) == staged }
      paths.each_with_index do |path, index|
        copy = "#{STATE}/previous/#{index}"
        kept << {path, @tree.copy(path, copy, path == CONFIG ? CONFIG_MAX : Tree::MAX_FILE) ? copy : nil}
      end
    end

    private def install_beside(manifest : Manifest, dir : String, kept : Array({String, String?})) : Nil
      if kept.any? { |path, _| path == manifest.proxy }
        File.open(File.join(dir, "cli-proxy-api")) { |io| @tree.write(manifest.proxy, io, Owner.root(0o755)) }
      end
      File.open(File.join(dir, "bundle", manifest.plugin_file)) do |io|
        @tree.write(manifest.plugin, io, @tree.owner(manifest.plugin) || Owner.root(0o644))
      end
    end

    private def switch(manifest : Manifest) : Nil
      drop_in = @tree.read(DROP_IN) || raise "the drop-in is gone"
      owner = @tree.owner(DROP_IN) || raise "the drop-in is gone"
      @tree.write(DROP_IN, drop_in.gsub(PROXY_PATH, manifest.proxy), owner)
    end

    private def restart_and_check(plugin_id : String, version : String?) : String?
      return "daemon-reload failed" unless @system.daemon_reload
      since = @system.now
      return "restart failed" unless @system.restart
      check(plugin_id, version, since)
    rescue ex
      "the check could not run: #{ex.message}"
    end

    # 6. Check, until it passes or the time is up; then again after a pause,
    # so a proxy that comes up and falls over does not pass.
    private def check(plugin_id : String, version : String?, since : Time) : String?
      deadline = @system.ticks + @check_within
      until (reason = check_once(plugin_id, version, since)).nil?
        return reason if @system.ticks >= deadline
        @system.sleep(@poll_every)
      end
      before = @system.unit_state
      @system.sleep(@settle)
      after = @system.unit_state
      return "cliproxyapi's MainPID and NRestarts could not be read" unless before && after
      return "cliproxyapi restarted within #{@settle.total_seconds.to_i} s of passing its check" unless after == before
      nil
    end

    private def check_once(plugin_id : String, version : String?, since : Time) : String?
      journal = @system.journal_since(since)
      unless journal.each_line.any? { |line| registered?(line, plugin_id, version) }
        return "plugin #{plugin_id} #{version} did not register".squeeze(' ')
      end
      return "the API server did not start" unless journal.includes?("API server started successfully")
      # Until its watcher runs, a management key write is saved but never goes live.
      return "the config watcher did not start" unless journal.includes?(WATCHER)
      pid = @system.unit_state.try(&.first) || 0_i64
      return "cliproxyapi is not running" unless pid > 0
      proxy = @tree.read(DROP_IN).try(&.[PROXY_PATH]?)
      exe = @system.exe(pid)
      return "cliproxyapi runs #{exe || "an unknown binary"}, not #{proxy}" unless exe && exe == proxy
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
      config = YAML.parse(@tree.read(CONFIG, CONFIG_MAX) || return)
      return unless config.as_h?
      host = config["host"]?.try(&.as_s?).presence || "127.0.0.1"
      port = config["port"]?.try(&.as_i?) || 8317
      host = "[#{host}]" if host.includes?(':')
      "http://#{host}:#{port}/v1/models"
    rescue
      nil
    end

    private def prepare_dirs : Nil
      {STATE => 0o755, "#{STATE}/moves" => 0o755, "#{STATE}/staging" => 0o700}.each do |dir, mode|
        Dir.mkdir_p(at(dir))
        File.chmod(at(dir), mode)
      end
    end

    private def record_path(move_id : String) : String
      "#{STATE}/moves/#{move_id}.json"
    end

    private def staging(move_id : String) : String
      at("#{STATE}/staging/#{move_id}")
    end

    private def sha256_of(path : String) : String
      File.open(path) { |io| sha256_of(io) }
    end

    private def sha256_of(io : IO) : String
      digest = Digest::SHA256.new
      buffer = Bytes.new(64 * 1024)
      while (read = io.read(buffer)) > 0
        digest.update(buffer[0, read])
      end
      digest.hexfinal
    end

    private def at(path : String) : String
      @root + path
    end
  end
end
