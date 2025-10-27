require "../rpc_client"
require "../storage"

module JJFS::Commands
  class List
    def initialize(@storage : Storage)
    end

    def execute
      client = RPCClient.new(@storage.socket_path)

      unless client.daemon_running?
        puts "Daemon: not running"
        puts "Start with: jjfs start"
        return false
      end

      result = client.call("list_mounts")
      mounts = result["mounts"].as_a

      if mounts.empty?
        puts "No mounts currently open"
        puts
        puts "Open a mount with: jjfs open <repo> [path]"
        return true
      end

      puts "Currently open mounts:"
      puts

      mounts.each do |mount|
        mount_hash = mount.as_h
        puts "  #{mount_hash["path"]}"
        puts "    Repo:   #{mount_hash["repo"]}"
        puts "    ID:     #{mount_hash["id"]}"
        puts "    Status: #{mount_hash["status"]}"
        puts
      end

      true
    rescue ex : Socket::ConnectError
      puts "Daemon: not running (connection refused)"
      puts "Start with: jjfs start"
      false
    rescue ex
      puts "Error: #{ex.message}"
      false
    end
  end
end
