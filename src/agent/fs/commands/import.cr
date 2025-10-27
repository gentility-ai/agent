require "../storage"
require "file_utils"
require "uri"

module AgentFS::Commands
  class Import
    def initialize(@storage : Storage, @git_url : String, @repo_name : String?)
    end

    def execute
      # Extract repo name from git URL if not provided
      name = @repo_name || extract_name_from_url(@git_url)

      unless name
        puts "Error: Could not extract repo name from URL. Please provide a name explicitly."
        puts "Usage: jjfs import <git-url> [name]"
        return false
      end

      repo_path = @storage.repo_path(name)

      # Check for naming conflict
      if @storage.config.repos.has_key?(name)
        puts "Error: Repo '#{name}' already exists"
        puts "Use a different name: jjfs import #{@git_url} <custom-name>"
        return false
      end

      if Dir.exists?(repo_path)
        puts "Error: Directory already exists at #{repo_path}"
        return false
      end

      puts "Importing #{@git_url} as '#{name}'..."

      # Clone the git repo
      stderr = IO::Memory.new
      result = Process.run("git", ["clone", @git_url, repo_path],
                          output: Process::Redirect::Pipe,
                          error: stderr)

      unless result.success?
        puts "Error: Failed to clone git repo: #{stderr}"
        FileUtils.rm_rf(repo_path) if Dir.exists?(repo_path)
        return false
      end

      # Initialize as jj repo (pointing to existing .git)
      stderr = IO::Memory.new
      result = Process.run("jj", ["git", "init", "--git-repo", repo_path],
                          output: Process::Redirect::Pipe,
                          error: stderr)

      unless result.success?
        puts "Error: Failed to initialize jj repo: #{stderr}"
        FileUtils.rm_rf(repo_path)
        return false
      end

      # Create workspaces directory
      FileUtils.mkdir_p(@storage.workspaces_dir(name))

      # Update config with remote URL
      @storage.config.repos[name] = RepoConfig.new(
        path: repo_path,
        remote: @git_url,
        sync_interval: 2,
        push_interval: 300
      )
      @storage.persist_config

      puts "✓ Imported repo '#{name}' at #{repo_path}"
      puts "  Remote: #{@git_url}"
      puts ""
      puts "Mount it with: jjfs open #{name} [path]"
      true
    end

    private def extract_name_from_url(url : String) : String?
      # Handle various git URL formats:
      # - https://github.com/user/repo.git
      # - git@github.com:user/repo.git
      # - https://github.com/user/repo
      # - /path/to/local/repo.git

      # Try to extract the last path component
      path = url

      # Remove .git suffix if present
      path = path.chomp(".git")

      # Handle SSH format (git@host:path)
      if path.includes?(":")
        parts = path.split(":")
        path = parts.last
      end

      # Handle HTTP(S) URLs
      if path.starts_with?("http://") || path.starts_with?("https://")
        begin
          uri = URI.parse(path)
          path = uri.path || ""
        rescue
          # Fall through to path splitting
        end
      end

      # Get the last component
      name = File.basename(path)

      # Return nil if we got nothing useful
      return nil if name.empty? || name == "/" || name == "."

      name
    end
  end
end
