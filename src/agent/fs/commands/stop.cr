module JJFS::Commands
  class Stop
    def execute
      {% if flag?(:darwin) %}
        stop_launchd
      {% elsif flag?(:linux) %}
        stop_systemd
      {% else %}
        puts "Error: Unsupported platform"
        false
      {% end %}
    end

    private def stop_launchd : Bool
      home = ENV["HOME"]
      plist = File.join(home, "Library", "LaunchAgents", "com.jjfs.daemon.plist")

      unless File.exists?(plist)
        puts "Error: Service not installed"
        puts "Run 'jjfs install' first"
        return false
      end

      stderr = IO::Memory.new
      result = Process.run("launchctl", ["unload", plist],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      if result.success?
        puts "Stopped jjfs daemon"
        true
      else
        error = stderr.to_s.strip
        if error.includes?("Could not find")
          puts "Daemon is not running"
          true
        else
          puts "Error: Failed to stop daemon: #{error}"
          false
        end
      end
    end

    private def stop_systemd : Bool
      stderr = IO::Memory.new
      result = Process.run("systemctl", ["--user", "stop", "jjfs"],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      if result.success?
        puts "Stopped jjfs daemon"
        true
      else
        puts "Error: Failed to stop daemon: #{stderr}"
        false
      end
    end
  end
end
