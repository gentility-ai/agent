require "process"

module JJFS
  class Watcher
    @running = false
    @process : Process?
    @fiber : Fiber?

    def initialize(@path : String, &@callback : String -> Void)
    end

    def start
      @running = true

      # Use fswatch on macOS, inotifywait on Linux
      cmd, args = detect_watcher_command

      @process = Process.new(cmd, args,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Pipe)

      if process = @process
        while @running
          if line = process.output.gets
            path = line.strip
            @callback.call(path) unless path.empty?
          else
            break
          end
        end
      end
    rescue ex
      # Handle process termination gracefully
      unless @running
        # Normal stop
      else
        raise ex
      end
    end

    def stop
      @running = false
      @process.try &.terminate
      @process.try &.wait
      @process = nil
    end

    private def detect_watcher_command : {String, Array(String)}
      # Check platform
      {% if flag?(:darwin) %}
        # macOS: use fswatch
        # -r: recursive
        # -l 0.1: latency in seconds (0.1s for faster response)
        {"fswatch", ["-r", "-l", "0.1", @path]}
      {% elsif flag?(:linux) %}
        # Linux: use inotifywait
        # -m: monitor continuously
        # -r: recursive
        # -e: event types
        {"inotifywait", ["-m", "-r", "-e", "modify,create,delete,move", @path]}
      {% else %}
        raise "Unsupported platform for file watching"
      {% end %}
    end
  end
end
