require "../storage"
require "file_utils"

module AgentFS::Commands
  class Init
    def initialize(@storage : Storage, @repo_name : String)
    end

    def execute
      repo_path = @storage.repo_path(@repo_name)

      if Dir.exists?(repo_path)
        puts "Error: Repo '#{@repo_name}' already exists at #{repo_path}"
        return false
      end

      # Create repo directory
      FileUtils.mkdir_p(repo_path)

      # Initialize jj repo
      stderr = IO::Memory.new
      result = Process.run("jj", ["git", "init", repo_path], output: Process::Redirect::Pipe, error: stderr)

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

      puts "Initialized repo '#{@repo_name}' at #{repo_path}"
      true
    end
  end
end
