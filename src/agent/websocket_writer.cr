require "http/web_socket"

class AgentWebSocketWriter
  # Keep only one frame buffered so a stuck socket write is noticed by the next
  # status, heartbeat, or command response instead of hiding behind a deep queue.
  DEFAULT_QUEUE_SIZE   = 1
  DEFAULT_SEND_TIMEOUT = 10.seconds

  def initialize(
    @websocket : HTTP::WebSocket,
    @queue_size : Int32 = DEFAULT_QUEUE_SIZE,
    @send_timeout : Time::Span = DEFAULT_SEND_TIMEOUT,
    @on_error : Proc(Exception, Nil)? = nil,
  )
    @channel = Channel(String).new(@queue_size)
    @closed = false
    spawn writer_loop
  end

  def send(json : String) : Bool
    return false if @closed

    select
    when @channel.send(json)
      true
    when timeout(@send_timeout)
      notify_error(IO::TimeoutError.new("Timed out queueing WebSocket frame"))
      false
    end
  rescue Channel::ClosedError
    false
  end

  def close : Nil
    return if @closed

    @closed = true
    @channel.close
  rescue Channel::ClosedError
  end

  private def writer_loop
    loop do
      json = @channel.receive
      @websocket.send(json)
    end
  rescue Channel::ClosedError
  rescue ex : Exception
    notify_error(ex)
  ensure
    close
  end

  private def notify_error(ex : Exception) : Nil
    was_closed = @closed
    close
    return if was_closed

    @on_error.try(&.call(ex))
  end
end
