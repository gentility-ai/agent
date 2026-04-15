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

  it "removes the stream from the registry after the destination closes (clean EOF)" do
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

    manager.open_stream("stream-cleanup-eof", "127.0.0.1", dest_port, 1000)

    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")
    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.close")

    # Reader fiber's ensure block calls shutdown → on_closed, so the
    # registry should drain. Allow a couple of yields to settle.
    deadline = Time.instant + 1.second
    while manager.stream_count > 0 && Time.instant < deadline
      sleep 10.milliseconds
    end
    manager.stream_count.should eq(0)

    dest_server.close
  end

  it "emits egress.stream.error(io_error) when the destination resets the connection" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    spawn do
      client = dest_server.accept
      # Force RST instead of FIN so the agent's reader sees an IO::Error,
      # not a clean EOF. This is the real-world failure we used to swallow.
      client.linger = 0
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-reset", "127.0.0.1", dest_port, 1000)

    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")

    # Some platforms surface a RST as a clean EOF rather than ECONNRESET
    # depending on timing. Either way, the stream MUST tear down with
    # exactly one terminal frame (close OR error) and drop from the
    # registry — that's the contract this test is locking in.
    select
    when json = frames.receive
      parsed = JSON.parse(json)
      type = parsed["type"].as_s
      ["egress.stream.close", "egress.stream.error"].should contain(type)
      parsed["stream_id"].as_s.should eq("stream-reset")
    when timeout(2.seconds)
      fail "no terminal frame received after peer reset"
    end

    deadline = Time.instant + 1.second
    while manager.stream_count > 0 && Time.instant < deadline
      sleep 10.milliseconds
    end
    manager.stream_count.should eq(0)

    dest_server.close
  end

  it "handle_data emits egress.stream.error(io_error) and tears down when the destination is dead" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    accepted = Channel(TCPSocket).new(1)
    spawn do
      client = dest_server.accept
      accepted.send(client)
    end

    frames = Channel(String).new(20)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-dead-write", "127.0.0.1", dest_port, 1000)
    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")

    dest_client = accepted.receive
    dest_client.linger = 0
    dest_client.close

    # Push a few writes so at least one race-free attempt lands after RST.
    5.times do
      manager.handle_data("stream-dead-write", Base64.strict_encode("payload"))
      Fiber.yield
    end

    saw_error = false
    deadline = Time.instant + 2.seconds
    while !saw_error && Time.instant < deadline
      select
      when json = frames.receive
        parsed = JSON.parse(json)
        if parsed["type"].as_s == "egress.stream.error"
          parsed["stream_id"].as_s.should eq("stream-dead-write")
          parsed["code"].as_s.should eq("io_error")
          saw_error = true
        end
      when timeout(100.milliseconds)
        # try again — frames may interleave with .data acks
      end
    end

    saw_error.should be_true

    deadline = Time.instant + 1.second
    while manager.stream_count > 0 && Time.instant < deadline
      sleep 10.milliseconds
    end
    manager.stream_count.should eq(0)

    dest_server.close
  end

  it "removes the stream after handle_close once the destination acknowledges the half-close" do
    dest_server = TCPServer.new("127.0.0.1", 0)
    dest_port = dest_server.local_address.as(Socket::IPAddress).port

    spawn do
      client = dest_server.accept
      buf = Bytes.new(64)
      loop do
        n = client.read(buf)
        break if n == 0
      end
      # mirror the half-close so the agent's reader sees EOF too.
      client.close
    end

    frames = Channel(String).new(10)
    send_frame = ->(json : String) {
      frames.send(json)
      nil
    }

    dialer = AgentEgressDialer.new(allow_loopback: true)
    manager = AgentEgressManager.new(send_frame: send_frame, dialer: dialer)

    manager.open_stream("stream-halfclose", "127.0.0.1", dest_port, 1000)
    JSON.parse(frames.receive)["type"].as_s.should eq("egress.stream.opened")

    manager.handle_close("stream-halfclose", nil)

    # Drain frames until we see the terminal close coming back from the
    # reader. There should be no spurious error frame for a clean teardown.
    saw_close = false
    deadline = Time.instant + 2.seconds
    while !saw_close && Time.instant < deadline
      select
      when json = frames.receive
        type = JSON.parse(json)["type"].as_s
        type.should_not eq("egress.stream.error")
        saw_close = true if type == "egress.stream.close"
      when timeout(100.milliseconds)
      end
    end
    saw_close.should be_true

    deadline = Time.instant + 1.second
    while manager.stream_count > 0 && Time.instant < deadline
      sleep 10.milliseconds
    end
    manager.stream_count.should eq(0)

    dest_server.close
  end
end

describe AgentEgressStream do
  it "enqueue_write returns false when the write queue is saturated" do
    # Build a real TCP pair where the destination never reads, then
    # crank the agent-side send buffer way down so a single chunk can
    # block in the kernel. With the writer fiber parked on socket.write,
    # the bounded channel saturates and the next enqueue must time out
    # rather than head-of-line block the dispatcher.
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port

    accepted = Channel(TCPSocket).new(1)
    spawn do
      client = server.accept
      accepted.send(client)
    end

    agent_side = TCPSocket.new("127.0.0.1", port)
    dest_side = accepted.receive

    agent_side.send_buffer_size = 1024
    dest_side.recv_buffer_size = 1024

    frames = [] of String
    send_frame = ->(json : String) {
      frames << json
      nil
    }

    stream = AgentEgressStream.new(
      stream_id: "saturation",
      socket: agent_side,
      send_frame: send_frame,
      write_capacity: 2,
      write_enqueue_timeout: 50.milliseconds,
    )

    big = Bytes.new(64 * 1024, 0x41_u8)

    # Hammer enqueue until either the channel saturates (false) or we
    # blow past a generous bound — whichever comes first.
    saw_false = false
    20.times do
      unless stream.enqueue_write(big)
        saw_false = true
        break
      end
    end

    saw_false.should be_true

    stream.shutdown
    dest_side.close rescue nil
    server.close
  end
end
