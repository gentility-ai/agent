require "uuid"
require "./storage"
require "./nfs_server"

module AgentFS
  class MountManager
    def initialize(@storage : Storage)
    end

    def mount(repo_name : String, mount_path : String) : MountConfig?
      # Validate repo exists
      repo = @storage.config.repos[repo_name]?
      unless repo
        puts "Error: Repo '#{repo_name}' not found"
        return nil
      end

      # Expand and validate mount path
      full_path = File.expand_path(mount_path)
      parent = File.dirname(full_path)

      unless Dir.exists?(parent)
        puts "Error: Parent directory #{parent} does not exist"
        return nil
      end

      if Dir.exists?(full_path) && !Dir.empty?(full_path)
        puts "Error: Mount point #{full_path} exists and is not empty"
        return nil
      end

      # Create mount point
      Dir.mkdir_p(full_path)

      # Create workspace
      workspace_id = UUID.random.to_s
      workspace_path = File.join(@storage.workspaces_dir(repo_name), workspace_id)

      # Add workspace to jj repo
      Dir.cd(repo.path) do
        error_io = IO::Memory.new
        result = Process.run("jj", ["workspace", "add", workspace_path],
                           output: Process::Redirect::Pipe,
                           error: error_io)

        unless result.success?
          puts "Error: Failed to create jj workspace: #{error_io.to_s}"
          Dir.delete(full_path) if Dir.exists?(full_path)
          return nil
        end
      end

      # Start NFS server for the workspace
      nfs_server = NFSServer.new(workspace_path)
      unless nfs_server.start
        puts "Error: Failed to start NFS server"
        Dir.delete(full_path) if Dir.exists?(full_path)
        return nil
      end

      # Mount via NFS (requires sudo password)
      puts "Mounting via NFS (sudo password required)..."
      mount_options = "nolocks,vers=3,tcp,port=#{nfs_server.port},mountport=#{nfs_server.port}"
      error_io = IO::Memory.new

      result = Process.run("sudo", ["mount_nfs", "-o", mount_options, "localhost:/", full_path],
                         output: Process::Redirect::Pipe,
                         error: error_io,
                         input: Process::Redirect::Close)

      unless result.success?
        puts "Error: Failed to mount via NFS: #{error_io.to_s}"
        nfs_server.stop
        Dir.delete(full_path) if Dir.exists?(full_path)
        return nil
      end

      # Create mount config
      mount_config = MountConfig.new(
        id: workspace_id,
        repo: repo_name,
        path: full_path,
        workspace: workspace_path,
        nfs_pid: nfs_server.pid,
        nfs_port: nfs_server.port
      )

      @storage.config.mounts << mount_config
      @storage.persist_config

      mount_config
    end

    def unmount(mount_path : String, timeout : Time::Span = 10.seconds) : Bool
      full_path = File.expand_path(mount_path)

      mount = @storage.config.mounts.find { |m| m.path == full_path }
      unless mount
        puts "Error: No mount found at #{full_path}"
        return false
      end

      # Stop NFS server first to avoid hanging unmount
      if pid = mount.nfs_pid
        begin
          Process.signal(Signal::TERM, pid.to_i)
          # Give it a moment to shutdown gracefully
          sleep 0.5.seconds
        rescue
          # Process might already be dead
        end
      end

      # Try unmount with timeout
      puts "Unmounting #{full_path}..."
      channel = Channel(Bool).new

      spawn do
        error_io = IO::Memory.new
        result = Process.run("sudo", ["umount", "-f", full_path],
                           output: Process::Redirect::Pipe,
                           error: error_io,
                           input: Process::Redirect::Close)
        channel.send(result.success?)
      end

      success = false
      select
      when result = channel.receive
        success = result
      when timeout(timeout)
        puts "Warning: Unmount command timed out after #{timeout.total_seconds}s"
        puts "The mount may still be active. This is a known macOS NFS issue."
        puts ""
        puts "Recovery options:"
        puts "  1. Try again: jjfs close #{full_path}"
        puts "  2. Force unmount: sudo umount -f #{full_path}"
        puts "  3. Reboot if mount is stuck"
        puts ""
        puts "Cleaning up NFS server and config anyway..."

        # Even if unmount hangs, we should clean up what we can
        success = false
      end

      unless success
        puts "Note: Removing mount from jjfs config, but filesystem may still be mounted."
        puts "Check with: mount | grep jjfs"
      end

      # Always clean up config and directory, even if unmount failed
      @storage.config.mounts.reject! { |m| m.path == full_path }
      @storage.persist_config

      # Try to remove mount point directory (will fail if still mounted)
      begin
        Dir.delete(full_path) if Dir.exists?(full_path)
      rescue
        # Directory might still be in use
      end

      success
    end
  end
end
