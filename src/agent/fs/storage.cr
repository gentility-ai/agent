require "file_utils"
require "./config"

module AgentFS
  class Storage
    DEFAULT_ROOT = File.join(ENV["HOME"], ".jjfs")

    getter root : String
    getter config : Config

    def initialize(@root : String = DEFAULT_ROOT)
      @config = load_config
    end

    def ensure_directories
      FileUtils.mkdir_p(repos_dir)
      FileUtils.mkdir_p(File.dirname(config_path))
      save_config unless File.exists?(config_path)
    end

    def repos_dir
      File.join(@root, "repos")
    end

    def config_path
      File.join(@root, "config.json")
    end

    def socket_path
      File.join(@root, "daemon.sock")
    end

    def lock_path
      File.join(@root, "daemon.lock")
    end

    def log_path
      File.join(@root, "sync.log")
    end

    def repo_path(name : String)
      File.join(repos_dir, name)
    end

    def workspaces_dir(repo : String)
      File.join(repo_path(repo), "workspaces")
    end

    private def load_config
      if File.exists?(config_path)
        Config.from_json(File.read(config_path))
      else
        Config.new
      end
    end

    private def save_config
      File.write(config_path, @config.to_json)
    end

    def persist_config
      save_config
    end

    def reload_config
      @config = load_config
    end
  end
end
