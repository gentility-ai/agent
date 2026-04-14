require "./spec_helper"
require "socket"

describe AgentEgressDialer do
  it "connects to a running local TCP server" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port

    accepted = Channel(Nil).new
    spawn do
      client = server.accept
      accepted.send(nil)
      client.close
    end

    dialer = AgentEgressDialer.new(allow_loopback: true)
    result = dialer.connect("127.0.0.1", port, 1.second)

    result.should be_a(AgentEgressDialer::Success)
    success = result.as(AgentEgressDialer::Success)
    success.remote_ip.should eq("127.0.0.1")
    success.remote_port.should eq(port)
    success.socket.should be_a(TCPSocket)

    select
    when accepted.receive
      # server saw the connection
    when timeout(1.second)
      fail "server never accepted"
    end

    success.socket.close
    server.close
  end

  it "returns Failure(connect_failed) when the target port refuses" do
    # Bind to get a free port, then close the server so connects will be refused.
    server = TCPServer.new("127.0.0.1", 0)
    port = server.local_address.as(Socket::IPAddress).port
    server.close

    dialer = AgentEgressDialer.new(allow_loopback: true)
    result = dialer.connect("127.0.0.1", port, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should_not be_empty
  end

  it "returns Failure(connect_failed) when DNS resolution fails" do
    dialer = AgentEgressDialer.new(allow_loopback: true)
    result = dialer.connect("this-host-does-not-exist-xyz123.invalid", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should_not be_empty
  end

  it "returns Failure(timeout) when the connect hangs past the budget" do
    # 192.0.2.1 is RFC5737 TEST-NET-1, guaranteed not routed on the public
    # internet — a connect to it should hang until the timeout fires.
    dialer = AgentEgressDialer.new(allow_loopback: true)
    result = dialer.connect("192.0.2.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("timeout")
    failure.message.should_not be_empty
  end

  # "Always denied" SSRF policy cluster — no network I/O, the Dialer
  # must reject these before attempting a connect.

  it "blocks loopback by default (IPv4)" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("127.0.0.1", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks link-local (cloud metadata 169.254.169.254)" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("169.254.169.254", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks IPv4 limited broadcast (255.255.255.255)" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("255.255.255.255", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks IPv4 multicast (224.0.0.1)" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("224.0.0.1", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks IPv4 wildcard range 0.0.0.0/8 (0.1.2.3)" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("0.1.2.3", 80, 1.second)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  # Conditional private-network gating + IPv6 coverage + v6-mapped-v4 unmap.

  it "blocks RFC1918 by default (allow_private_networks defaults to false)" do
    # Locks in the default-deny posture: a Dialer constructed without any
    # arguments must refuse private network destinations. The agent's
    # egress config has to opt in explicitly.
    dialer = AgentEgressDialer.new
    result = dialer.connect("10.0.0.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks RFC1918 10/8 when allow_private_networks is false" do
    dialer = AgentEgressDialer.new(allow_private_networks: false)
    result = dialer.connect("10.0.0.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks CGNAT 100.64/10 when allow_private_networks is false" do
    dialer = AgentEgressDialer.new(allow_private_networks: false)
    result = dialer.connect("100.64.0.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks IPv6 ULA fc00::/7 when allow_private_networks is false" do
    dialer = AgentEgressDialer.new(allow_private_networks: false)
    result = dialer.connect("fc00::1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks IPv6 multicast ff00::/8" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("ff02::1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  it "blocks v6-mapped-v4 loopback ::ffff:127.0.0.1 by default" do
    dialer = AgentEgressDialer.new
    result = dialer.connect("::ffff:127.0.0.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end

  # THE bypass: stdlib private? does NOT unmap v6-mapped-v4, so without
  # explicit unmap logic, ::ffff:10.0.0.1 would sail through the policy
  # while allow_private_networks=false. This test pins down that we detect
  # the mapping and re-check against v4 rules.
  it "blocks v6-mapped-v4 RFC1918 ::ffff:10.0.0.1 when allow_private_networks is false" do
    dialer = AgentEgressDialer.new(allow_private_networks: false)
    result = dialer.connect("::ffff:10.0.0.1", 80, 300.milliseconds)

    result.should be_a(AgentEgressDialer::Failure)
    failure = result.as(AgentEgressDialer::Failure)
    failure.code.should eq("connect_failed")
    failure.message.should contain("blocked")
  end
end
