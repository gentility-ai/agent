require "../mount_manager"

module AgentFS::Commands
  class Close
    def initialize(@storage : Storage, @path : String)
    end

    def execute
      manager = MountManager.new(@storage)
      manager.unmount(@path)
    end
  end
end
