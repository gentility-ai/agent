require "base64"
require "json"
require "socket"

class AgentEgressStream
  CHUNK_SIZE                    = 32 * 1024
  DEFAULT_WRITE_QUEUE_CAPACITY  =     64
  DEFAULT_WRITE_ENQUEUE_TIMEOUT = 50.milliseconds

  alias OnClosed = Proc(String, Nil)

  getter stream_id : String
  getter socket : TCPSocket

  @closed : Bool = false
  @error_emitted : Bool = false

  def initialize(
    @stream_id : String,
    @socket : TCPSocket,
    @send_frame : Proc(String, Nil),
    @on_closed : OnClosed = ->(_id : String) { nil },
    write_capacity : Int32 = DEFAULT_WRITE_QUEUE_CAPACITY,
    @write_enqueue_timeout : Time::Span = DEFAULT_WRITE_ENQUEUE_TIMEOUT,
  )
    @write_channel = Channel(Bytes).new(write_capacity)
    spawn reader_loop
    spawn writer_loop
  end

  def closed? : Bool
    @closed
  end

  # Try to enqueue bytes for the destination. Returns false if the write
  # queue is saturated past the timeout — caller should then tear the
  # stream down so a single slow destination cannot stall the dispatcher.
  def enqueue_write(bytes : Bytes) : Bool
    return false if @closed

    select
    when @write_channel.send(bytes)
      true
    when timeout(@write_enqueue_timeout)
      false
    end
  rescue Channel::ClosedError
    false
  end

  # Half-close the outbound (agent → destination) direction. The writer
  # fiber drains any already-queued bytes, then shuts down the socket's
  # write side. The reader stays alive until the peer closes its half.
  def half_close_write : Nil
    @write_channel.close
  rescue Channel::ClosedError
    # already half-closed
  end

  # Tear the stream fully down. Idempotent across reader/writer paths.
  def shutdown : Nil
    return if @closed
    @closed = true
    @write_channel.close rescue nil
    @socket.close rescue nil
    @on_closed.call(@stream_id)
  end

  private def reader_loop
    buf = Bytes.new(CHUNK_SIZE)
    loop do
      n = @socket.read(buf)
      if n == 0
        send_close unless @closed
        break
      end
      send_data(buf[0, n])
    end
  rescue ex : IO::Error
    emit_error_once("io_error", ex.message || "destination read failed")
  ensure
    shutdown
  end

  private def writer_loop
    loop do
      bytes = @write_channel.receive?
      break unless bytes
      @socket.write(bytes)
    end
    @socket.close_write rescue nil
  rescue ex : IO::Error
    emit_error_once("io_error", ex.message || "destination write failed")
    shutdown
  end

  private def emit_error_once(code : String, message : String) : Nil
    return if @error_emitted || @closed
    @error_emitted = true
    send_error(code, message)
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

  private def send_error(code : String, message : String) : Nil
    frame = {
      "type"      => "egress.stream.error",
      "v"         => 3,
      "stream_id" => @stream_id,
      "code"      => code,
      "message"   => message,
    }
    @send_frame.call(frame.to_json)
  end
end
