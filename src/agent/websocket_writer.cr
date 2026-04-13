require "http/web_socket"

class AgentWebSocketWriter
  def initialize(@websocket : HTTP::WebSocket)
    @channel = Channel(String).new
    spawn writer_loop
  end

  def send(json : String) : Nil
    @channel.send(json)
  rescue Channel::ClosedError
  end

  def close : Nil
    @channel.close
  end

  private def writer_loop
    loop do
      json = @channel.receive
      @websocket.send(json)
    end
  rescue Channel::ClosedError
  end
end
