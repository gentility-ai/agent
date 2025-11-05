require "socket"
require "json"

module AgentFS
  class RPCClient
    def initialize(@socket_path : String)
    end

    def call(method : String, params = {} of String => String) : JSON::Any
      request = {
        "jsonrpc" => "2.0",
        "method" => method,
        "params" => params,
        "id" => 1
      }.to_json

      socket = UNIXSocket.new(@socket_path)
      socket.puts(request)
      response = socket.gets
      socket.close

      raise "No response from daemon" unless response

      data = JSON.parse(response)

      if error = data["error"]?
        raise "RPC Error: #{error["message"]}"
      end

      data["result"]
    end

    def daemon_running? : Bool
      File.exists?(@socket_path)
    end
  end
end
