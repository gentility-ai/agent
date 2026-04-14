require "base64"
require "json"
require "socket"

class AgentEgressStream
  CHUNK_SIZE = 32 * 1024

  getter stream_id : String
  getter socket : TCPSocket

  def initialize(@stream_id : String, @socket : TCPSocket, @send_frame : Proc(String, Nil))
    spawn reader_loop
  end

  private def reader_loop
    buf = Bytes.new(CHUNK_SIZE)
    loop do
      n = @socket.read(buf)
      if n == 0
        send_close
        break
      end
      send_data(buf[0, n])
    end
  rescue IO::Error
    # destination read failure — fiber exits; follow-up cycle wires
    # egress.stream.error emission.
  end

  private def send_data(bytes : Bytes) : Nil
    frame = {
      "type"        => "egress.stream.data",
      "v"           => 3,
      "stream_id"   => @stream_id,
      "payload_b64" => Base64.strict_encode(bytes),
    }
    @send_frame.call(frame.to_json)
  end

  private def send_close : Nil
    frame = {
      "type"      => "egress.stream.close",
      "v"         => 3,
      "stream_id" => @stream_id,
    }
    @send_frame.call(frame.to_json)
  end
end
