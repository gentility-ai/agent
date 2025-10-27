module JJFS::Commands
  class Start
    def execute
      {% if flag?(:darwin) %}
        start_launchd
      {% elsif flag?(:linux) %}
        start_systemd
      {% else %}
        puts "Error: Unsupported platform"
        false
      {% end %}
    end

    private def start_launchd : Bool
      home = ENV["HOME"]
      plist = File.join(home, "Library", "LaunchAgents", "com.jjfs.daemon.plist")

      unless File.exists?(plist)
        puts "Error: Service not installed"
        puts "Run 'jjfs install' first"
        return false
      end

      stderr = IO::Memory.new
      result = Process.run("launchctl", ["load", plist],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      if result.success?
        puts "Started jjfs daemon"
        true
      else
        error = stderr.to_s.strip
        if error.includes?("already loaded")
          puts "Daemon is already running"
          true
        else
          puts "Error: Failed to start daemon: #{error}"
          false
        end
      end
    end

    private def start_systemd : Bool
      stderr = IO::Memory.new
      result = Process.run("systemctl", ["--user", "start", "jjfs"],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      if result.success?
        puts "Started jjfs daemon"
        true
      else
        puts "Error: Failed to start daemon: #{stderr}"
        false
      end
    end
  end
end
