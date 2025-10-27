require "json"
require "./storage"

module JJFS
  class RPCServer
    def initialize(@storage : Storage, @sync_coordinator : SyncCoordinator? = nil)
    end

    def handle(request : String) : String
      req = JSON.parse(request)
      method = req["method"].as_s

      response = case method
      when "status"
        handle_status
      when "list_mounts"
        handle_list_mounts
      else
        {"error" => "Unknown method: #{method}"}
      end

      {
        "jsonrpc" => "2.0",
        "result" => response,
        "id" => req["id"]?
      }.to_json
    rescue ex
      {
        "jsonrpc" => "2.0",
        "error" => {"message" => ex.message},
        "id" => nil
      }.to_json
    end

    private def handle_status
      # Reload config to get current state from disk
      @storage.reload_config

      {
        "daemon" => "running",
        "repos" => @storage.config.repos.size,
        "mounts" => @storage.config.mounts.size
      }
    end

    private def handle_list_mounts
      # Reload config to get current state from disk
      @storage.reload_config

      {
        "mounts" => @storage.config.mounts.map do |m|
          {
            "id" => m.id,
            "repo" => m.repo,
            "path" => m.path,
            "status" => check_mount_status(m)
          }
        end
      }
    end

    private def check_mount_status(mount : MountConfig) : String
      # Check if actually mounted
      output = IO::Memory.new
      Process.run("mount", output: output, error: Process::Redirect::Close)
      is_mounted = output.to_s.lines.any? { |line| line.includes?(mount.path) }

      # Check if NFS server is running
      server_running = false
      if pid = mount.nfs_pid
        check = Process.run("kill", ["-0", pid.to_s],
                          output: Process::Redirect::Close,
                          error: Process::Redirect::Close)
        server_running = check.success?
      end

      if is_mounted && server_running
        "active"
      elsif is_mounted && !server_running
        "stale (server dead)"
      elsif !is_mounted && server_running
        "inconsistent (unmounted but server running)"
      else
        "inactive"
      end
    end
  end
end
