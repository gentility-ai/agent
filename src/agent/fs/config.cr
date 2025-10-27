require "json"

module JJFS
  class RepoConfig
    include JSON::Serializable

    property path : String
    property remote : String?
    property sync_interval : Int32
    property push_interval : Int32

    def initialize(@path : String, @remote : String? = nil, @sync_interval : Int32 = 2, @push_interval : Int32 = 300)
    end
  end

  class MountConfig
    include JSON::Serializable

    property id : String
    property repo : String
    property path : String
    property workspace : String
    property nfs_pid : Int64?
    property nfs_port : Int32?

    def initialize(@id : String, @repo : String, @path : String, @workspace : String, @nfs_pid : Int64? = nil, @nfs_port : Int32? = nil)
    end
  end

  class Config
    include JSON::Serializable

    property repos : Hash(String, RepoConfig)
    property mounts : Array(MountConfig)

    def initialize
      @repos = {} of String => RepoConfig
      @mounts = [] of MountConfig
    end
  end
end
