require "file_utils"

module AgentFS::Commands
  class Install
    def execute
      jjfsd_path = find_jjfsd
      unless jjfsd_path
        puts "Error: jjfsd not found in PATH"
        puts "Please ensure jjfsd is built and installed in your PATH"
        return false
      end

      {% if flag?(:darwin) %}
        install_launchd(jjfsd_path)
      {% elsif flag?(:linux) %}
        install_systemd(jjfsd_path)
      {% else %}
        puts "Error: Unsupported platform"
        puts "Service installation is only supported on macOS and Linux"
        false
      {% end %}
    end

    private def find_jjfsd : String?
      # Check if jjfsd is in PATH
      stdout = IO::Memory.new
      result = Process.run("which", ["jjfsd"],
                         output: stdout,
                         error: Process::Redirect::Pipe)

      if result.success?
        path = stdout.to_s.strip
        path.empty? ? nil : path
      else
        nil
      end
    end

    private def install_launchd(jjfsd_path : String) : Bool
      # Find template file relative to this source file or in current directory
      template_path = find_template("com.jjfs.daemon.plist")
      unless template_path
        puts "Error: Could not find template file com.jjfs.daemon.plist"
        puts "Expected in: templates/com.jjfs.daemon.plist"
        return false
      end

      template = File.read(template_path)
      content = template
        .gsub("{{JJFSD_PATH}}", jjfsd_path)
        .gsub("{{HOME}}", ENV["HOME"])

      # Ensure LaunchAgents directory exists
      home = ENV["HOME"]
      launch_agents_dir = File.join(home, "Library", "LaunchAgents")
      FileUtils.mkdir_p(launch_agents_dir)

      plist_path = File.join(launch_agents_dir, "com.jjfs.daemon.plist")
      File.write(plist_path, content)

      puts "Installed service file to #{plist_path}"

      # Load service
      stderr = IO::Memory.new
      result = Process.run("launchctl", ["load", plist_path],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      unless result.success?
        error = stderr.to_s.strip
        # Ignore "already loaded" errors
        if error.includes?("already loaded")
          puts "Service already loaded, reloading..."
          Process.run("launchctl", ["unload", plist_path])
          sleep 0.5.seconds
          stderr2 = IO::Memory.new
          result = Process.run("launchctl", ["load", plist_path],
                             output: Process::Redirect::Pipe,
                             error: stderr2)
          unless result.success?
            puts "Error: Failed to load service: #{stderr2}"
            return false
          end
        else
          puts "Error: Failed to load service: #{error}"
          return false
        end
      end

      puts "Successfully installed and started jjfs service (launchd)"
      puts "The daemon will start automatically on login"
      true
    end

    private def install_systemd(jjfsd_path : String) : Bool
      # Find template file
      template_path = find_template("jjfs.service")
      unless template_path
        puts "Error: Could not find template file jjfs.service"
        puts "Expected in: templates/jjfs.service"
        return false
      end

      template = File.read(template_path)
      content = template
        .gsub("{{JJFSD_PATH}}", jjfsd_path)
        .gsub("{{HOME}}", ENV["HOME"])

      # Ensure systemd user directory exists
      home = ENV["HOME"]
      systemd_dir = File.join(home, ".config", "systemd", "user")
      FileUtils.mkdir_p(systemd_dir)

      service_path = File.join(systemd_dir, "jjfs.service")
      File.write(service_path, content)

      puts "Installed service file to #{service_path}"

      # Reload systemd
      stderr = IO::Memory.new
      result = Process.run("systemctl", ["--user", "daemon-reload"],
                         output: Process::Redirect::Pipe,
                         error: stderr)

      unless result.success?
        puts "Warning: Failed to reload systemd: #{stderr}"
      end

      # Enable and start
      stderr2 = IO::Memory.new
      result = Process.run("systemctl", ["--user", "enable", "--now", "jjfs"],
                         output: Process::Redirect::Pipe,
                         error: stderr2)

      unless result.success?
        puts "Error: Failed to enable service: #{stderr2}"
        return false
      end

      puts "Successfully installed and started jjfs service (systemd)"
      puts "The daemon will start automatically on login"
      true
    end

    private def find_template(filename : String) : String?
      # Check common locations for templates
      paths = [
        File.join("templates", filename),
        File.join("..", "templates", filename),
        File.join(Dir.current, "templates", filename),
      ]

      paths.each do |path|
        return path if File.exists?(path)
      end

      nil
    end
  end
end
