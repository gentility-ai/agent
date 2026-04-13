require "./spec_helper"
require "socket"

module AgentWebSocketWriterSpecHelpers
  def perform_server_handshake(socket : TCPSocket) : Nil
    headers = {} of String => String

    while line = socket.gets("\r\n", chomp: true)
      break if line.empty?

      parts = line.split(":", 2)
      next unless parts.size == 2

      headers[parts[0]] = parts[1].strip
    end

    key = headers["Sec-WebSocket-Key"]? || raise "client did not send Sec-WebSocket-Key"
    accept = HTTP::WebSocket::Protocol.key_challenge(key)

    socket << "HTTP/1.1 101 Switching Protocols\r\n"
    socket << "Upgrade: websocket\r\n"
    socket << "Connection: Upgrade\r\n"
    socket << "Sec-WebSocket-Accept: #{accept}\r\n"
    socket << "\r\n"
    socket.flush
  end
end

include AgentWebSocketWriterSpecHelpers

describe AgentWebSocketWriter do
  it "delivers a single message to the underlying websocket" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    received = Channel(String).new(10)

    server_done = Channel(Nil).new

    spawn do
      begin
        client = server.accept
        perform_server_handshake(client)

        ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(client, masked: false))
        ws.on_message { |msg| received.send(msg) }
        ws.run
      rescue ex
        # surface in the test if it matters
        received.send("ERROR: #{ex.class}: #{ex.message}")
      ensure
        server_done.send(nil)
      end
    end

    client_ws = AgentWebSocketConnector.open(
      URI.parse("ws://127.0.0.1:#{port}/"),
      connect_timeout: 1.second,
      handshake_timeout: 1.second,
      write_timeout: 1.second
    )

    writer = AgentWebSocketWriter.new(client_ws)
    writer.send("hello")

    select
    when msg = received.receive
      msg.should eq("hello")
    when timeout(2.seconds)
      fail "did not receive message within 2 seconds"
    end

    client_ws.close
    server.close
    server_done.receive
  end

  it "delivers all messages sent before close in order" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    received = Channel(String).new(10)
    server_done = Channel(Nil).new

    spawn do
      begin
        client = server.accept
        perform_server_handshake(client)

        ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(client, masked: false))
        ws.on_message { |msg| received.send(msg) }
        ws.run
      rescue ex
        received.send("ERROR: #{ex.class}: #{ex.message}")
      ensure
        server_done.send(nil)
      end
    end

    client_ws = AgentWebSocketConnector.open(
      URI.parse("ws://127.0.0.1:#{port}/"),
      connect_timeout: 1.second,
      handshake_timeout: 1.second,
      write_timeout: 1.second
    )

    writer = AgentWebSocketWriter.new(client_ws)
    writer.send("first")
    writer.send("second")
    writer.send("third")
    writer.close

    messages = [] of String
    3.times do
      select
      when msg = received.receive
        messages << msg
      when timeout(2.seconds)
        fail "did not receive all messages within 2 seconds (got #{messages.size}: #{messages})"
      end
    end

    messages.should eq(["first", "second", "third"])

    client_ws.close
    server.close
    server_done.receive
  end

  it "silently drops sends after close without raising" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    received = Channel(String).new(10)
    server_done = Channel(Nil).new

    spawn do
      begin
        client = server.accept
        perform_server_handshake(client)

        ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(client, masked: false))
        ws.on_message { |msg| received.send(msg) }
        ws.run
      rescue ex
        received.send("ERROR: #{ex.class}: #{ex.message}")
      ensure
        server_done.send(nil)
      end
    end

    client_ws = AgentWebSocketConnector.open(
      URI.parse("ws://127.0.0.1:#{port}/"),
      connect_timeout: 1.second,
      handshake_timeout: 1.second,
      write_timeout: 1.second
    )

    writer = AgentWebSocketWriter.new(client_ws)

    writer.send("before")
    select
    when msg = received.receive
      msg.should eq("before")
    when timeout(2.seconds)
      fail "did not receive 'before' within 2 seconds"
    end

    writer.close

    # These must not raise
    writer.send("after-close-1")
    writer.send("after-close-2")

    # And nothing should arrive at the server
    select
    when unexpected = received.receive
      fail "unexpected message after close: #{unexpected}"
    when timeout(300.milliseconds)
      # good — nothing arrived
    end

    client_ws.close
    server.close
    server_done.receive
  end
end
