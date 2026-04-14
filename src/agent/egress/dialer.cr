require "socket"

class AgentEgressDialer
  record Success, socket : TCPSocket, remote_ip : String, remote_port : Int32
  record Failure, code : String, message : String

  alias Result = Success | Failure

  def initialize(@allow_loopback : Bool = false, @allow_private_networks : Bool = true)
  end

  def connect(host : String, port : Int32, timeout : Time::Span) : Result
    addrinfos = Socket::Addrinfo.tcp(host, port, timeout: timeout)
    ai = addrinfos.first
    ip = ai.ip_address

    if reason = blocked_by_policy?(ip)
      return Failure.new("connect_failed", "destination blocked by policy: #{reason}")
    end

    socket = TCPSocket.new(family: ai.family)
    begin
      socket.connect(ai, timeout: timeout)
    rescue ex : IO::TimeoutError
      socket.close rescue nil
      return Failure.new("timeout", ex.message || "connection timed out")
    rescue ex : Socket::ConnectError
      socket.close rescue nil
      return Failure.new("connect_failed", ex.message || "connection failed")
    end

    Success.new(socket, ip.address, ip.port)
  rescue ex : Socket::Addrinfo::Error
    Failure.new("connect_failed", ex.message || "dns resolution failed")
  end

  private def blocked_by_policy?(ip : Socket::IPAddress) : String?
    # Unmap v6-mapped-v4 first. stdlib's ip.private? does NOT unmap, so
    # without this ::ffff:10.0.0.1 would bypass allow_private_networks.
    canonical = unmap_v6_to_v4(ip) || ip

    return "loopback" if canonical.loopback? && !@allow_loopback
    return "link_local" if canonical.link_local?

    case canonical.family
    when Socket::Family::INET
      v4_ranges(canonical)
    when Socket::Family::INET6
      v6_ranges(canonical)
    else
      nil
    end
  end

  private def v4_ranges(ip : Socket::IPAddress) : String?
    addr = ip.address
    return "ipv4_broadcast" if addr == "255.255.255.255"

    octets = addr.split('.').map(&.to_i)
    first = octets[0]?
    return "ipv4_wildcard_0/8" if first == 0
    return "ipv4_multicast_224/4" if first && first >= 224 && first <= 239

    return nil if @allow_private_networks

    return "rfc1918" if ip.private?
    second = octets[1]?
    return "cgnat_100.64/10" if first == 100 && second && second >= 64 && second < 128

    nil
  end

  private def v6_ranges(ip : Socket::IPAddress) : String?
    return "ipv6_multicast_ff00/8" if ip.address.starts_with?("ff")

    return nil if @allow_private_networks
    return "ipv6_ula_fc00/7" if ip.private?

    nil
  end

  private def unmap_v6_to_v4(ip : Socket::IPAddress) : Socket::IPAddress?
    return nil unless ip.family == Socket::Family::INET6
    addr = ip.address
    return nil unless addr.starts_with?("::ffff:") && addr.includes?('.')

    v4_str = addr[7..]
    Socket::IPAddress.new(v4_str, ip.port)
  end
end
