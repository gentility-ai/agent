require "../mount_manager"
require "../storage"

module AgentFS::Commands
  class Open
    def initialize(@storage : Storage, @repo_name : String, @path : String?)
    end

    def execute
      # Default path: ./<repo_name>
      mount_path = @path || File.join(Dir.current, @repo_name)

      # Check if we're in a git repo and offer to add to .gitignore
      check_and_offer_gitignore(mount_path)

      manager = MountManager.new(@storage)

      if mount = manager.mount(@repo_name, mount_path)
        puts "Opened #{@repo_name} at #{mount.path}"
        true
      else
        false
      end
    end

    private def check_and_offer_gitignore(mount_path : String)
      # Find .git directory by walking up from mount_path parent
      parent_dir = File.dirname(File.expand_path(mount_path))
      git_dir = find_git_directory(parent_dir)

      return unless git_dir

      # We're in a git repo
      gitignore_path = File.join(git_dir, ".gitignore")
      mount_name = File.basename(mount_path)

      # Check if already in .gitignore
      if File.exists?(gitignore_path)
        content = File.read(gitignore_path)
        return if content.lines.any? { |line| line.strip == mount_name || line.strip == "/#{mount_name}" }
      end

      # Offer to add to .gitignore
      puts "\n⚠️  Warning: You're opening a mount inside a git repository."
      puts "   To avoid polluting this repo with synced content, add to .gitignore?"
      puts "   Add '/#{mount_name}' to #{gitignore_path}? [Y/n]"
      print "> "

      response = gets.try(&.strip.downcase) || "y"

      if response.empty? || response == "y" || response == "yes"
        add_to_gitignore(gitignore_path, mount_name)
        puts "✓ Added '/#{mount_name}' to .gitignore"
      else
        puts "Skipped - remember to manually add '/#{mount_name}' to .gitignore!"
      end
    end

    private def find_git_directory(start_path : String) : String?
      current = start_path

      # Walk up to root looking for .git
      loop do
        git_path = File.join(current, ".git")
        return current if Dir.exists?(git_path) || File.exists?(git_path)

        parent = File.dirname(current)
        break if parent == current # Reached root
        current = parent
      end

      nil
    end

    private def add_to_gitignore(gitignore_path : String, mount_name : String)
      # Ensure newline at end if file exists
      if File.exists?(gitignore_path)
        content = File.read(gitignore_path)
        content += "\n" unless content.ends_with?("\n")
        File.write(gitignore_path, content + "/#{mount_name}\n")
      else
        File.write(gitignore_path, "/#{mount_name}\n")
      end
    end
  end
end
