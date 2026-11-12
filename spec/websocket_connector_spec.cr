require "./spec_helper"
require "socket"

module WebSocketConnectorSpecHelpers
  def read_http_headers(socket : TCPSocket) : Hash(String, String)
    headers = {} of String => String

    while line = socket.gets("\r\n", chomp: true)
      break if line.empty?

      parts = line.split(":", 2)
      next unless parts.size == 2

      headers[parts[0]] = parts[1].strip
    end

    headers
  end
end

include WebSocketConnectorSpecHelpers

describe AgentWebSocketConnector do
  it "opens a websocket when the server completes the upgrade" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    done = Channel(Nil).new

    spawn do
      client = server.accept
      begin
        headers = read_http_headers(client)
        key = headers["Sec-WebSocket-Key"]?
        raise "Missing Sec-WebSocket-Key" unless key

        accept = HTTP::WebSocket::Protocol.key_challenge(key)
        client << "HTTP/1.1 101 Switching Protocols\r\n"
        client << "Upgrade: websocket\r\n"
        client << "Connection: Upgrade\r\n"
        client << "Sec-WebSocket-Accept: #{accept}\r\n"
        client << "\r\n"
        client.flush
      ensure
        client.close rescue nil
        done.send(nil)
      end
    end

    begin
      ws = AgentWebSocketConnector.open(
        URI.parse("ws://127.0.0.1:#{port}/agent/websocket?version=test"),
        connect_timeout: 1.second,
        handshake_timeout: 1.second,
        write_timeout: 1.second
      )

      ws.closed?.should be_false
      ws.close
    ensure
      server.close
      done.receive
    end
  end

  it "sends the credential in the Authorization header and leaves the URL as given" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    request = Channel({String, Hash(String, String)}).new(1)

    spawn do
      client = server.accept
      begin
        request_line = client.gets("\r\n", chomp: true) || ""
        headers = read_http_headers(client)
        request.send({request_line, headers})

        accept = HTTP::WebSocket::Protocol.key_challenge(headers["Sec-WebSocket-Key"])
        client << "HTTP/1.1 101 Switching Protocols\r\n"
        client << "Upgrade: websocket\r\n"
        client << "Connection: Upgrade\r\n"
        client << "Sec-WebSocket-Accept: #{accept}\r\n"
        client << "\r\n"
        client.flush
      ensure
        client.close rescue nil
      end
    end

    begin
      ws = AgentWebSocketConnector.open(
        URI.parse("ws://127.0.0.1:#{port}/agent/websocket?version=5"),
        connect_timeout: 1.second,
        handshake_timeout: 1.second,
        write_timeout: 1.second,
        authorization: AgentWebSocketConnector.authorization("genkey-agent-spec", nil)
      )
      ws.close

      request_line, headers = request.receive
      request_line.should eq("GET /agent/websocket?version=5 HTTP/1.1")
      headers["Authorization"].should eq("Machine-Key genkey-agent-spec")
    ensure
      server.close
    end
  end

  it "names a machine key and an OAuth token by their own schemes" do
    AgentWebSocketConnector.authorization("genkey-agent-spec", nil).should eq("Machine-Key genkey-agent-spec")
    AgentWebSocketConnector.authorization(nil, "oauth-spec").should eq("Bearer oauth-spec")
    AgentWebSocketConnector.authorization(nil, nil).should be_nil
  end

  it "times out when the server accepts a socket but never finishes the handshake" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    done = Channel(Nil).new

    spawn do
      client = server.accept
      begin
        sleep 1.second
      ensure
        client.close rescue nil
        done.send(nil)
      end
    end

    begin
      expect_raises(IO::TimeoutError, /WebSocket handshake/) do
        AgentWebSocketConnector.open(
          URI.parse("ws://127.0.0.1:#{port}/agent/websocket"),
          connect_timeout: 200.milliseconds,
          handshake_timeout: 200.milliseconds,
          write_timeout: 200.milliseconds
        )
      end
    ensure
      server.close
      done.receive
    end
  end
end
