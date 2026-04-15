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

  def stream_count : Int32
    @streams.size
  end

  def open_stream(stream_id : String, host : String, port : Int32, connect_timeout_ms : Int32) : Nil
    spawn do
      result = @dialer.connect(host, port, connect_timeout_ms.milliseconds)
      case result
      when AgentEgressDialer::Success
        on_closed = ->(id : String) {
          @streams.delete(id)
          nil
        }
        stream = AgentEgressStream.new(
          stream_id: stream_id,
          socket: result.socket,
          send_frame: @send_frame,
          on_closed: on_closed,
        )
        @streams[stream_id] = stream
        send_opened(stream_id, result.remote_ip, result.remote_port)
      when AgentEgressDialer::Failure
        send_error(stream_id, result.code, result.message)
      end
    end
  end

  def handle_data(stream_id : String, payload_b64 : String) : Nil
    stream = @streams[stream_id]?
    unless stream
      send_error(stream_id, "stream_not_found", "no such stream")
      return
    end

    bytes = Base64.decode(payload_b64)
    unless stream.enqueue_write(bytes)
      send_error(stream_id, "io_error", "agent write queue saturated")
      stream.shutdown
    end
  end

  def handle_close(stream_id : String, reason : String? = nil) : Nil
    stream = @streams[stream_id]?
    unless stream
      send_error(stream_id, "stream_not_found", "no such stream")
      return
    end
    stream.half_close_write
  end

  def close_all : Nil
    # Snapshot first so the on_closed callback can mutate @streams freely
    # while we iterate. shutdown is idempotent and yields, so iterating
    # the live hash directly would race with its own delete.
    streams = @streams.values
    @streams.clear
    streams.each(&.shutdown)
  end

  private def send_opened(stream_id : String, remote_ip : String, remote_port : Int32) : Nil
    frame = {
      "type"        => "egress.stream.opened",
      "stream_id"   => stream_id,
      "remote_ip"   => remote_ip,
      "remote_port" => remote_port,
    }
    @send_frame.call(frame.to_json)
  end

  private def send_error(stream_id : String, code : String, message : String) : Nil
    frame = {
      "type"      => "egress.stream.error",
      "stream_id" => stream_id,
      "code"      => code,
      "message"   => message,
    }
    @send_frame.call(frame.to_json)
  end
end
