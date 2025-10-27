require "./storage"
require "log"

module AgentFS
  class RemoteSyncer
    Log = ::Log.for(self)

    @running = false

    def initialize(@storage : Storage)
    end

    def start
      @running = true

      spawn do
        while @running
          sync_all_repos
          sleep 300.seconds  # 5 minutes (push_interval from config)
        end
      end

      Log.info { "Remote syncer started" }
    end

    def stop
      @running = false
      Log.info { "Remote syncer stopped" }
    end

    def sync_repo(repo_name : String) : Bool
      repo = @storage.config.repos[repo_name]?
      return false unless repo
      return true unless repo.remote  # No remote configured, skip

      # Find first workspace for this repo to use for git operations
      mount = @storage.config.mounts.find { |m| m.repo == repo_name }
      unless mount
        Log.warn { "No mount found for repo #{repo_name}, skipping remote sync" }
        return false
      end

      Dir.cd(mount.workspace) do
        # Push all bookmarks
        Log.info { "Pushing #{repo_name} to remote..." }
        stderr = IO::Memory.new
        result = Process.run("jj", ["git", "push", "--all-bookmarks"],
                           output: Process::Redirect::Pipe,
                           error: stderr)

        unless result.success?
          error_msg = stderr.to_s.strip
          # Don't log as error if there's nothing to push
          if error_msg.includes?("Nothing changed")
            Log.debug { "No changes to push for #{repo_name}" }
          else
            Log.error { "Failed to push #{repo_name}: #{error_msg}" }
            return false
          end
        end

        # Fetch from remote
        Log.info { "Fetching #{repo_name} from remote..." }
        stderr2 = IO::Memory.new
        result = Process.run("jj", ["git", "fetch"],
                           output: Process::Redirect::Pipe,
                           error: stderr2)

        unless result.success?
          Log.error { "Failed to fetch #{repo_name}: #{stderr2}" }
          return false
        end

        # Rebase if there are remote changes
        stderr3 = IO::Memory.new
        result = Process.run("jj", ["rebase"],
                           output: Process::Redirect::Pipe,
                           error: stderr3)

        unless result.success?
          # Rebase may fail if there's nothing to rebase, which is fine
          Log.debug { "Rebase result for #{repo_name}: #{stderr3}" }
        end

        Log.info { "Successfully synced #{repo_name} with remote" }
        true
      end
    end

    private def sync_all_repos
      @storage.config.repos.each_key do |repo_name|
        sync_repo(repo_name)
      end
    end
  end
end
