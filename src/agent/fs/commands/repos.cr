require "../rpc_client"
require "../storage"

module AgentFS::Commands
  class Repos
    def initialize(@storage : Storage)
    end

    def execute
      # Reload config to get current repos
      @storage.reload_config

      if @storage.config.repos.empty?
        puts "No repos found"
        puts
        puts "Create a new repo:"
        puts "  jjfs new <name>          - Create new jj repo"
        puts "  jjfs import <git-url>    - Import existing git repo"
        return true
      end

      puts "Available repos:"
      puts

      @storage.config.repos.each do |name, repo|
        puts "  #{name}"
        puts "    Path:   #{repo.path}"
        if remote = repo.remote
          puts "    Remote: #{remote}"
        end
        puts
      end

      true
    end
  end
end
