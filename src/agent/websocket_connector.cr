module AgentWebSocketConnector
  extend self

  DEFAULT_DNS_TIMEOUT       = 5.seconds
  DEFAULT_CONNECT_TIMEOUT   = 10.seconds
  DEFAULT_HANDSHAKE_TIMEOUT = 15.seconds
  DEFAULT_WRITE_TIMEOUT     = 10.seconds

  def open(
    uri : URI,
    dns_timeout : Time::Span = DEFAULT_DNS_TIMEOUT,
    connect_timeout : Time::Span = DEFAULT_CONNECT_TIMEOUT,
    handshake_timeout : Time::Span = DEFAULT_HANDSHAKE_TIMEOUT,
    write_timeout : Time::Span = DEFAULT_WRITE_TIMEOUT
  ) : HTTP::WebSocket
    host = uri.hostname || raise ArgumentError.new("WebSocket URI is missing a host")
    path = uri.request_target
    path = "/" if path.empty?
    tls = uri.scheme.in?("https", "wss")
    port = uri.port || (tls ? 443 : 80)

    headers = HTTP::Headers.new
    if (user = uri.user) && (password = uri.password)
      headers["Authorization"] = "Basic #{Base64.strict_encode("#{user}:#{password}")}"
    end

    transport = open_transport(host, port, tls, dns_timeout, connect_timeout, handshake_timeout)

    begin
      perform_handshake(transport, host, port, path, headers)
      configure_session_timeouts(transport, write_timeout)
      HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(transport, true))
    rescue ex
      close_transport(transport)
      raise ex
    end
  end

  private def open_transport(
    host : String,
    port : Int32,
    tls : Bool,
    dns_timeout : Time::Span,
    connect_timeout : Time::Span,
    handshake_timeout : Time::Span
  ) : TCPSocket | OpenSSL::SSL::Socket::Client
    socket = TCPSocket.new(host, port, dns_timeout, connect_timeout)
    socket.read_timeout = handshake_timeout
    socket.write_timeout = handshake_timeout
    socket.sync = false

    return socket unless tls

    ssl_socket = OpenSSL::SSL::Socket::Client.new(
      socket,
      context: OpenSSL::SSL::Context::Client.new,
      sync_close: true,
      hostname: host
    )
    ssl_socket.read_timeout = handshake_timeout
    ssl_socket.write_timeout = handshake_timeout
    ssl_socket.sync = false
    ssl_socket
  rescue ex : IO::TimeoutError
    raise IO::TimeoutError.new("Timed out connecting to #{host}:#{port}")
  end

  private def perform_handshake(
    transport : IO,
    host : String,
    port : Int32,
    path : String,
    headers : HTTP::Headers
  ) : Nil
    random_key = Base64.strict_encode(StaticArray(UInt8, 16).new { rand(256).to_u8 })

    headers["Host"] = "#{host}:#{port}"
    headers["Connection"] = "Upgrade"
    headers["Upgrade"] = "websocket"
    headers["Sec-WebSocket-Version"] = HTTP::WebSocket::Protocol::VERSION
    headers["Sec-WebSocket-Key"] = random_key

    request = HTTP::Request.new("GET", path, headers)
    request.to_io(transport)
    transport.flush

    response = HTTP::Client::Response.from_io(transport, ignore_body: true)
    unless response.status.switching_protocols?
      raise Socket::Error.new("Handshake got denied. Status code was #{response.status.code}.")
    end

    expected_accept = HTTP::WebSocket::Protocol.key_challenge(random_key)
    unless response.headers["Sec-WebSocket-Accept"]? == expected_accept
      raise Socket::Error.new("Handshake got denied. Server did not verify WebSocket challenge.")
    end
  rescue ex : IO::TimeoutError
    raise IO::TimeoutError.new("Timed out waiting for WebSocket handshake from #{host}:#{port}")
  end

  private def configure_session_timeouts(transport : IO, write_timeout : Time::Span) : Nil
    case transport
    when TCPSocket, OpenSSL::SSL::Socket::Client
      transport.read_timeout = nil
      transport.write_timeout = write_timeout
    end
  end

  private def close_transport(transport : IO) : Nil
    transport.close
  rescue IO::Error
  end
end
