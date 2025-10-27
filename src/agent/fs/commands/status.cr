require "../rpc_client"
require "../storage"

module JJFS::Commands
  class Status
    def initialize(@storage : Storage)
    end

    def execute
      client = RPCClient.new(@storage.socket_path)

      unless client.daemon_running?
        puts "Daemon: not running"
        puts "Start with: jjfs start"
        return false
      end

      result = client.call("status")

      puts "Daemon: running"
      puts "Repos: #{result["repos"]}"
      puts "Mounts: #{result["mounts"]}"

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
