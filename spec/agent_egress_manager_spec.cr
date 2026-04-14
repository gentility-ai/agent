require "./spec_helper"
require "socket"
require "json"

describe AgentEgressManager do
  it "sends egress.stream.opened when open_stream succeeds" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    accepted = Channel(Nil).new
    spawn do
      client = dest_server.accept
      accepted.send(nil)
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-1", "127.0.0.1", dest_port, 1000)

    select
    when json = frames.receive
      parsed = JSON.parse(json)
      parsed["type"].as_s.should eq("egress.stream.opened")
      parsed["v"].as_i.should eq(3)
      parsed["stream_id"].as_s.should eq("stream-1")
      parsed["remote_ip"]?.try(&.as_s).should eq("127.0.0.1")
      parsed["remote_port"]?.try(&.as_i).should eq(dest_port)
    when timeout(2.seconds)
      fail "no frame received within 2s"
    end

    select
    when accepted.receive
      # destination saw the connection
    when timeout(1.second)
      fail "destination server never accepted"
    end

    dest_server.close
  end

  it "sends egress.stream.error when open_stream dial fails" do
    # Bind to grab a free port, then close so subsequent connects refuse.
    probe = TCPServer.new("127.0.0.1", 0)
    dead_port = probe.local_address.as(Socket::IPAddress).port
    probe.close

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-2", "127.0.0.1", dead_port, 500)

    select
    when json = frames.receive
      parsed = JSON.parse(json)
      parsed["type"].as_s.should eq("egress.stream.error")
      parsed["v"].as_i.should eq(3)
      parsed["stream_id"].as_s.should eq("stream-2")
      parsed["code"].as_s.should eq("connect_failed")
      parsed["message"].as_s.should_not be_empty
    when timeout(2.seconds)
      fail "no frame received within 2s"
    end
  end

  it "handle_data writes decoded bytes to the destination socket" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    dest_reads = Channel(String).new(10)
    spawn do
      client = dest_server.accept
      buf = Bytes.new(64)
      n = client.read(buf)
      dest_reads.send(String.new(buf[0, n]))
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-3", "127.0.0.1", dest_port, 1000)

    # Wait for opened frame so we know the stream is registered.
    select
    when frames.receive
      # good
    when timeout(2.seconds)
      fail "no opened frame"
    end

    manager.handle_data("stream-3", Base64.strict_encode("hello"))

    select
    when got = dest_reads.receive
      got.should eq("hello")
    when timeout(2.seconds)
      fail "destination never received bytes"
    end

    dest_server.close
  end

  it "forwards destination bytes as egress.stream.data frames" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    spawn do
      client = dest_server.accept
      client.write("hi there".to_slice)
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-4", "127.0.0.1", dest_port, 1000)

    # Drain opened frame.
    opened_json = frames.receive
    JSON.parse(opened_json)["type"].as_s.should eq("egress.stream.opened")

    select
    when data_json = frames.receive
      parsed = JSON.parse(data_json)
      parsed["type"].as_s.should eq("egress.stream.data")
      parsed["v"].as_i.should eq(3)
      parsed["stream_id"].as_s.should eq("stream-4")
      decoded = String.new(Base64.decode(parsed["payload_b64"].as_s))
      decoded.should eq("hi there")
    when timeout(2.seconds)
      fail "no data frame received"
    end

    dest_server.close
  end

  it "sends egress.stream.close when the destination closes its write side" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    spawn do
      client = dest_server.accept
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-5", "127.0.0.1", dest_port, 1000)

    # Drain opened.
    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")

    select
    when close_json = frames.receive
      parsed = JSON.parse(close_json)
      parsed["type"].as_s.should eq("egress.stream.close")
      parsed["v"].as_i.should eq(3)
      parsed["stream_id"].as_s.should eq("stream-5")
    when timeout(2.seconds)
      fail "no close frame received"
    end

    dest_server.close
  end

  it "handle_close half-closes the outbound direction to the destination" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    dest_saw_eof = Channel(Nil).new
    spawn do
      client = dest_server.accept
      buf = Bytes.new(64)
      loop do
        n = client.read(buf)
        break if n == 0
      end
      dest_saw_eof.send(nil)
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-6", "127.0.0.1", dest_port, 1000)
    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")

    manager.handle_close("stream-6", nil)

    select
    when dest_saw_eof.receive
      # good
    when timeout(2.seconds)
      fail "destination never observed EOF after handle_close"
    end

    dest_server.close
  end

  it "close_all fully closes every open stream" do
    dest_a = TCPServer.new("127.0.0.1", 0)
    port_a = dest_a.local_address.as(Socket::IPAddress).port

    dest_b = TCPServer.new("127.0.0.1", 0)
    port_b = dest_b.local_address.as(Socket::IPAddress).port

    eof_a = Channel(Nil).new
    eof_b = Channel(Nil).new

    spawn do
      client = dest_a.accept
      buf = Bytes.new(64)
      loop do
        n = client.read(buf)
        break if n == 0
      end
      eof_a.send(nil)
      client.close
    end

    spawn do
      client = dest_b.accept
      buf = Bytes.new(64)
      loop do
        n = client.read(buf)
        break if n == 0
      end
      eof_b.send(nil)
      client.close
    end

    frames = Channel(String).new(20)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-A", "127.0.0.1", port_a, 1000)
    manager.open_stream("stream-B", "127.0.0.1", port_b, 1000)

    # Drain the two opened frames so we know both streams registered.
    2.times { frames.receive }

    manager.close_all

    select
    when eof_a.receive
    when timeout(2.seconds)
      fail "dest A never saw EOF"
    end

    select
    when eof_b.receive
    when timeout(2.seconds)
      fail "dest B never saw EOF"
    end

    dest_a.close
    dest_b.close
  end

  it "handle_data with unknown stream_id emits egress.stream.error(stream_not_found)" do
    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    manager = AgentEgressManager.new(send_frame: send_frame)

    manager.handle_data("ghost", Base64.strict_encode("hi"))

    select
    when json = frames.receive
      parsed = JSON.parse(json)
      parsed["type"].as_s.should eq("egress.stream.error")
      parsed["stream_id"].as_s.should eq("ghost")
      parsed["code"].as_s.should eq("stream_not_found")
    when timeout(1.second)
      fail "no error frame received"
    end
  end

  it "handle_close with unknown stream_id emits egress.stream.error(stream_not_found)" do
    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    manager = AgentEgressManager.new(send_frame: send_frame)

    manager.handle_close("phantom", nil)

    select
    when json = frames.receive
      parsed = JSON.parse(json)
      parsed["type"].as_s.should eq("egress.stream.error")
      parsed["stream_id"].as_s.should eq("phantom")
      parsed["code"].as_s.should eq("stream_not_found")
    when timeout(1.second)
      fail "no error frame received"
    end
  end
end
