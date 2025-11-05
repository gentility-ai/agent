require "../storage"

module AgentFS::Commands
  class Remote
    def initialize(@storage : Storage, @args : Array(String))
    end

    def execute
      action = @args.first?

      case action
      when "add"
        add_remote
      else
        puts "Usage: jjfs remote add <url> [--repo=name]"
        puts ""
        puts "Examples:"
        puts "  jjfs remote add git@github.com:user/repo.git"
        puts "  jjfs remote add https://github.com/user/repo.git --repo=default"
        false
      end
    end

    private def add_remote
      url = @args[1]?
      unless url
        puts "Error: URL required"
        return false
      end

      # Parse --repo option
      repo_name = "default"
      @args.each do |arg|
        if arg.starts_with?("--repo=")
          repo_name = arg.split("=", 2)[1]
        end
      end

      repo = @storage.config.repos[repo_name]?
      unless repo
        puts "Error: Repo '#{repo_name}' not found"
        puts "Available repos: #{@storage.config.repos.keys.join(", ")}"
        return false
      end

      # Set git remote in the repo
      Dir.cd(repo.path) do
        # First check if remote already exists
        stdout = IO::Memory.new
        result = Process.run("jj", ["git", "remote", "list"],
                           output: stdout,
                           error: Process::Redirect::Pipe)

        if result.success? && stdout.to_s.includes?("origin")
          # Remove existing remote
          Process.run("jj", ["git", "remote", "remove", "origin"],
                     output: Process::Redirect::Pipe,
                     error: Process::Redirect::Pipe)
        end

        # Add new remote
        stderr = IO::Memory.new
        result = Process.run("jj", ["git", "remote", "add", "origin", url],
                           output: Process::Redirect::Pipe,
                           error: stderr)

        unless result.success?
          puts "Error: Failed to add remote: #{stderr}"
          return false
        end
      end

      # Update config
      repo.remote = url
      @storage.persist_config

      puts "Added remote '#{url}' to repo '#{repo_name}'"
      puts "Remote sync will occur every #{repo.push_interval} seconds"
      true
    end
  end
end
