require "base64"
require "json"
require "socket"
require "./dialer"
require "./stream"

class AgentEgressManager
  alias SendFrame = Proc(String, Nil)

  def initialize(@send_frame : SendFrame, @dialer : AgentEgressDialer = AgentEgressDialer.new)
    @streams = {} of String => AgentEgressStream
  end

  def open_stream(stream_id : String, host : String, port : Int32, connect_timeout_ms : Int32) : Nil
    spawn do
      result = @dialer.connect(host, port, connect_timeout_ms.milliseconds)
      case result
      when AgentEgressDialer::Success
        stream = AgentEgressStream.new(stream_id, result.socket, @send_frame)
        @streams[stream_id] = stream
        send_opened(stream_id, result.remote_ip, result.remote_port)
      when AgentEgressDialer::Failure
        send_error(stream_id, result.code, result.message)
      end
    end
  end

  def handle_data(stream_id : String, payload_b64 : String) : Nil
    with_stream(stream_id) do |stream|
      bytes = Base64.decode(payload_b64)
      stream.socket.write(bytes)
    end
  end

  def handle_close(stream_id : String, reason : String? = nil) : Nil
    with_stream(stream_id) do |stream|
      stream.socket.close_write rescue nil
    end
  end

  def close_all : Nil
    @streams.each_value do |stream|
      stream.socket.close rescue nil
    end
    @streams.clear
  end

  private def with_stream(stream_id : String, &block : AgentEgressStream ->) : Nil
    stream = @streams[stream_id]?
    unless stream
      send_error(stream_id, "stream_not_found", "no such stream")
      return
    end
    block.call(stream)
  end

  private def send_opened(stream_id : String, remote_ip : String, remote_port : Int32) : Nil
    frame = {
      "type"        => "egress.stream.opened",
      "v"           => 3,
      "stream_id"   => stream_id,
      "remote_ip"   => remote_ip,
      "remote_port" => remote_port,
    }
    @send_frame.call(frame.to_json)
  end

  private def send_error(stream_id : String, code : String, message : String) : Nil
    frame = {
      "type"      => "egress.stream.error",
      "v"         => 3,
      "stream_id" => stream_id,
      "code"      => code,
      "message"   => message,
    }
    @send_frame.call(frame.to_json)
  end
end
