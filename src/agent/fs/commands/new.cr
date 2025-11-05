require "../storage"
require "file_utils"

module AgentFS::Commands
  class New
    def initialize(@storage : Storage, @repo_name : String)
    end

    def execute
      repo_path = @storage.repo_path(@repo_name)

      # Check for naming conflict
      if @storage.config.repos.has_key?(@repo_name)
        puts "Error: Repo '#{@repo_name}' already exists"
        puts "Choose a different name or use: jjfs open #{@repo_name} [path]"
        return false
      end

      if Dir.exists?(repo_path)
        puts "Error: Directory already exists at #{repo_path}"
        return false
      end

      puts "Creating new jj repo '#{@repo_name}'..."

      # Create repo directory
      FileUtils.mkdir_p(repo_path)

      # Initialize jj repo with git backend
      stderr = IO::Memory.new
      result = Process.run("jj", ["git", "init", repo_path],
                          output: Process::Redirect::Pipe,
                          error: stderr)

      unless result.success?
        puts "Error: Failed to initialize jj repo: #{stderr}"
        FileUtils.rm_rf(repo_path)
        return false
      end

      # Create workspaces directory
      FileUtils.mkdir_p(@storage.workspaces_dir(@repo_name))

      # Update config
      @storage.config.repos[@repo_name] = RepoConfig.new(
        path: repo_path,
        remote: nil,
        sync_interval: 2,
        push_interval: 300
      )
      @storage.persist_config

      puts "✓ Created repo '#{@repo_name}' at #{repo_path}"
      puts ""
      puts "Mount it with: jjfs open #{@repo_name} [path]"
      true
    end
  end
end
