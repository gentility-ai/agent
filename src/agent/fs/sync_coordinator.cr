require "./storage"
require "./watcher"
require "log"

module JJFS
  class SyncCoordinator
    Log = ::Log.for(self)

    @watchers = [] of Watcher
    @syncing = Set(String).new  # Track workspaces being synced to prevent loops

    def initialize(@storage : Storage)
    end

    def start
      # Start watchers for each mount
      @storage.config.mounts.each do |mount|
        start_watcher(mount)
      end

      Log.info { "Sync coordinator started with #{@watchers.size} watchers" }
    end

    def stop
      @watchers.each &.stop
      @watchers.clear
      Log.info { "Sync coordinator stopped" }
    end

    def add_mount(mount : MountConfig)
      start_watcher(mount)
      Log.info { "Added watcher for mount #{mount.id}" }
    end

    def remove_mount(mount : MountConfig)
      # Stop watcher for this mount (simplified - track by workspace)
      # TODO: Implement proper watcher tracking and removal
      Log.info { "Removed watcher for mount #{mount.id}" }
    end

    private def start_watcher(mount : MountConfig)
      # Only start watcher if workspace directory exists
      return unless Dir.exists?(mount.workspace)

      watcher = Watcher.new(mount.workspace) do |changed_path|
        handle_change(mount, changed_path)
      end

      spawn { watcher.start }
      @watchers << watcher
    end

    private def handle_change(mount : MountConfig, changed_path : String)
      # Prevent sync loops - if we're already syncing this workspace, skip
      return if @syncing.includes?(mount.workspace)

      Log.info { "Change detected in #{mount.workspace}: #{changed_path}" }

      @syncing.add(mount.workspace)

      begin
        # Commit changes in this workspace
        commit_workspace(mount)

        # Sync to other workspaces in same repo
        sync_repo_workspaces(mount.repo, mount.workspace)
      ensure
        @syncing.delete(mount.workspace)
      end
    end

    private def commit_workspace(mount : MountConfig)
      Dir.cd(mount.workspace) do
        timestamp = Time.utc.to_s("%Y-%m-%d %H:%M:%S")

        io = IO::Memory.new
        result = Process.run("jj", ["commit", "-m", "auto-sync #{timestamp}"],
                           output: io,
                           error: io)

        if result.success?
          Log.info { "Committed changes in #{mount.workspace}" }
        else
          Log.error { "Failed to commit in #{mount.workspace}: #{io}" }
        end
      end
    rescue ex
      Log.error { "Error committing workspace #{mount.workspace}: #{ex.message}" }
    end

    private def sync_repo_workspaces(repo_name : String, source_workspace : String)
      # Find all other workspaces for this repo
      other_mounts = @storage.config.mounts.select do |m|
        m.repo == repo_name && m.workspace != source_workspace
      end

      other_mounts.each do |mount|
        # Mark this workspace as syncing to prevent feedback loop
        @syncing.add(mount.workspace)

        begin
          Dir.cd(mount.workspace) do
            io = IO::Memory.new
            result = Process.run("jj", ["workspace", "update-stale"],
                                 output: io,
                                 error: io)

            if result.success?
              Log.info { "Synced changes to #{mount.workspace}" }
            else
              Log.error { "Failed to update workspace #{mount.workspace}: #{io}" }
            end
          end
        ensure
          @syncing.delete(mount.workspace)
        end
      end
    rescue ex
      Log.error { "Error syncing repo workspaces: #{ex.message}" }
    end
  end
end
