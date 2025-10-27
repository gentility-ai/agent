require "process"

module JJFS
  class NFSServer
    getter port : Int32
    getter pid : Int64?

    @process : Process?
    @workspace_path : String

    def initialize(@workspace_path : String)
      @port = find_available_port
      @pid = nil
      @process = nil
    end

    def start : Bool
      # Find jjfs-nfs binary (should be in same directory as jjfs)
      bin_dir = File.dirname(Process.executable_path.not_nil!)
      nfs_binary = File.join(bin_dir, "jjfs-nfs")

      unless File.exists?(nfs_binary)
        puts "Error: jjfs-nfs binary not found at #{nfs_binary}"
        return false
      end

      # Start the NFS server process
      @process = Process.new(
        nfs_binary,
        ["--port", @port.to_s, @workspace_path],
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Pipe
      )

      @pid = @process.not_nil!.pid

      # Wait for NFS_READY signal
      ready = wait_for_ready(@process.not_nil!)

      unless ready
        stop
        return false
      end

      true
    end

    def stop
      if proc = @process
        proc.terminate
        proc.wait
        @process = nil
        @pid = nil
      end
    end

    private def wait_for_ready(process : Process) : Bool
      # Read from stdout looking for NFS_READY=1
      timeout = 5.seconds
      start_time = Time.monotonic

      # Wait up to 5 seconds for ready signal
      while Time.monotonic - start_time < timeout
        if line = process.output.gets
          return true if line.includes?("NFS_READY=1")
        end
        sleep 0.1
      end

      false
    end

    private def find_available_port : Int32
      # Find an available port by binding to port 0 and seeing what we get
      server = TCPServer.new("127.0.0.1", 0)
      port = server.local_address.port
      server.close
      port
    end
  end
end
