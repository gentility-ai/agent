# Filesystem Mount Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate jjfs functionality into the Gentility agent to provide unified filesystem mount management with org-scoped repos and dual communication channels (WebSocket + Unix socket).

**Architecture:** Lift and shift jjfs code into src/agent/fs/, rename modules to AgentFS::*, add Unix socket RPC server alongside existing WebSocket server, implement org-scoped repo naming (org_slug/shared), and provide simple CLI commands (agent open ., agent close ., agent status).

**Tech Stack:** Crystal, Jujutsu (jj), NFS (mount_nfs), fswatch/inotify, Unix sockets, JSON-RPC 2.0, Rust (jjfs-nfs binary)

---

## Prerequisites

Before starting implementation, verify:
- [ ] Design document reviewed: `docs/plans/2025-10-27-fs-integration-design.md`
- [ ] Working in worktree: `.worktrees/fs-integration`
- [ ] Branch: `feature/fs-integration`
- [ ] Dependencies installed: `shards install` completed

## Implementation Tasks

### Task 1: Copy jjfs Source Code

**Files:**
- Create: `src/agent/fs/` (directory)
- Copy from: `../../jjfs/src/*.cr` → `src/agent/fs/`
- Copy from: `../../jjfs/src/commands/*.cr` → `src/agent/fs/commands/`

**Step 1: Create directory structure**

```bash
mkdir -p src/agent/fs/commands
```

**Step 2: Copy core jjfs files**

```bash
cp ../../jjfs/src/config.cr src/agent/fs/
cp ../../jjfs/src/storage.cr src/agent/fs/
cp ../../jjfs/src/mount_manager.cr src/agent/fs/
cp ../../jjfs/src/nfs_server.cr src/agent/fs/
cp ../../jjfs/src/sync_coordinator.cr src/agent/fs/
cp ../../jjfs/src/watcher.cr src/agent/fs/
cp ../../jjfs/src/remote_syncer.cr src/agent/fs/
cp ../../jjfs/src/rpc_server.cr src/agent/fs/
cp ../../jjfs/src/rpc_client.cr src/agent/fs/
```

**Step 3: Copy command files**

```bash
cp ../../jjfs/src/commands/*.cr src/agent/fs/commands/
```

**Step 4: Verify files copied**

```bash
ls -la src/agent/fs/
ls -la src/agent/fs/commands/
```

Expected: 9 files in fs/, all command files in commands/

**Step 5: Commit**

```bash
git add src/agent/fs/
git commit -m "Copy jjfs source code to src/agent/fs/

Copied all core modules and commands from jjfs for integration.
Next: rename modules JJFS -> AgentFS and update paths."
```

---

### Task 2: Create AgentFS Module Namespace

**Files:**
- Create: `src/agent/fs.cr`

**Step 1: Create module wrapper**

Create `src/agent/fs.cr`:

```crystal
# MIT License
#
# Copyright (c) 2025 Gentility AI
#
# [standard MIT license text - same as agent.cr]

# Filesystem mount management
# Integrated from jjfs for unified agent functionality

module AgentFS
  VERSION = "0.1.0"
end

# Core components
require "./fs/config"
require "./fs/storage"
require "./fs/mount_manager"
require "./fs/nfs_server"
require "./fs/sync_coordinator"
require "./fs/watcher"
require "./fs/remote_syncer"
require "./fs/rpc_server"
require "./fs/rpc_client"

# Commands
require "./fs/commands/*"
```

**Step 2: Add require to agent.cr**

In `src/agent.cr`, after line 44 (after other agent requires), add:

```crystal
require "./agent/fs"
```

**Step 3: Verify it compiles (expect failures)**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | head -30
```

Expected: Errors about JJFS module not found (this is correct - we'll fix next)

**Step 4: Commit**

```bash
git add src/agent/fs.cr src/agent.cr
git commit -m "Add AgentFS module namespace

Created AgentFS module and required it in agent.
Currently fails to compile - next step: rename JJFS -> AgentFS."
```

---

### Task 3: Rename JJFS Module to AgentFS in config.cr

**Files:**
- Modify: `src/agent/fs/config.cr`

**Step 1: Replace module declaration**

In `src/agent/fs/config.cr`, replace:

```crystal
module JJFS
```

with:

```crystal
module AgentFS
```

**Step 2: Update BASE_DIR constant**

Find the line with `BASE_DIR` (likely around line 10-20), replace:

```crystal
BASE_DIR = Path.home / ".jjfs"
```

with:

```crystal
BASE_DIR = if Process.uid == 0
  Path.new("/var/lib/gentility/fs")
else
  Path.home / ".config" / "gentility" / "fs"
end
```

**Step 3: Update SOCKET_PATH constant**

Find `SOCKET_PATH`, replace:

```crystal
SOCKET_PATH = BASE_DIR / "daemon.sock"
```

with:

```crystal
SOCKET_PATH = if Process.uid == 0
  Path.new("/run/gentility/agent.sock")
else
  Path.home / ".config" / "gentility" / "agent.sock"
end
```

**Step 4: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "config.cr" | head -10
```

Expected: Still errors, but not syntax errors in config.cr

**Step 5: Commit**

```bash
git add src/agent/fs/config.cr
git commit -m "Rename JJFS to AgentFS in config.cr

Updated module namespace and paths:
- ~/.jjfs -> ~/.config/gentility/fs (user)
- Added /var/lib/gentility/fs support (system)"
```

---

### Task 4: Rename JJFS to AgentFS in storage.cr

**Files:**
- Modify: `src/agent/fs/storage.cr`

**Step 1: Replace module declaration**

In `src/agent/fs/storage.cr`, replace:

```crystal
module JJFS
```

with:

```crystal
module AgentFS
```

**Step 2: Replace all JJFS:: references**

Run search and replace in the file:

```bash
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/storage.cr
```

**Step 3: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "storage.cr" | head -10
```

**Step 4: Commit**

```bash
git add src/agent/fs/storage.cr
git commit -m "Rename JJFS to AgentFS in storage.cr"
```

---

### Task 5: Rename JJFS to AgentFS in mount_manager.cr

**Files:**
- Modify: `src/agent/fs/mount_manager.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/mount_manager.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/mount_manager.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "mount_manager" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/mount_manager.cr
git commit -m "Rename JJFS to AgentFS in mount_manager.cr"
```

---

### Task 6: Rename JJFS to AgentFS in nfs_server.cr

**Files:**
- Modify: `src/agent/fs/nfs_server.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/nfs_server.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/nfs_server.cr
```

**Step 2: Update NFS binary path**

Find where the NFS binary is referenced (likely `jjfs-nfs`), update to look in multiple locations:

```crystal
def nfs_binary_path : String
  # Try bundled location first
  bundled = Path.new(Process.executable_path).parent / "jjfs-nfs"
  return bundled.to_s if File.exists?(bundled)

  # Try libexec location
  libexec = Path.new("/usr/local/libexec/gentility/jjfs-nfs")
  return libexec.to_s if File.exists?(libexec)

  # Fall back to PATH
  "jjfs-nfs"
end
```

**Step 3: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "nfs_server" | head -10
```

**Step 4: Commit**

```bash
git add src/agent/fs/nfs_server.cr
git commit -m "Rename JJFS to AgentFS in nfs_server.cr

Added smart NFS binary path resolution."
```

---

### Task 7: Rename JJFS to AgentFS in sync_coordinator.cr

**Files:**
- Modify: `src/agent/fs/sync_coordinator.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/sync_coordinator.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/sync_coordinator.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "sync_coordinator" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/sync_coordinator.cr
git commit -m "Rename JJFS to AgentFS in sync_coordinator.cr"
```

---

### Task 8: Rename JJFS to AgentFS in watcher.cr

**Files:**
- Modify: `src/agent/fs/watcher.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/watcher.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/watcher.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "watcher" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/watcher.cr
git commit -m "Rename JJFS to AgentFS in watcher.cr"
```

---

### Task 9: Rename JJFS to AgentFS in remote_syncer.cr

**Files:**
- Modify: `src/agent/fs/remote_syncer.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/remote_syncer.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/remote_syncer.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "remote_syncer" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/remote_syncer.cr
git commit -m "Rename JJFS to AgentFS in remote_syncer.cr"
```

---

### Task 10: Rename JJFS to AgentFS in rpc_server.cr

**Files:**
- Modify: `src/agent/fs/rpc_server.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/rpc_server.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/rpc_server.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "rpc_server" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/rpc_server.cr
git commit -m "Rename JJFS to AgentFS in rpc_server.cr"
```

---

### Task 11: Rename JJFS to AgentFS in rpc_client.cr

**Files:**
- Modify: `src/agent/fs/rpc_client.cr`

**Step 1: Replace module and references**

```bash
sed -i '' 's/module JJFS/module AgentFS/g' src/agent/fs/rpc_client.cr
sed -i '' 's/JJFS::/AgentFS::/g' src/agent/fs/rpc_client.cr
```

**Step 2: Verify syntax**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | grep -i "rpc_client" | head -10
```

**Step 3: Commit**

```bash
git add src/agent/fs/rpc_client.cr
git commit -m "Rename JJFS to AgentFS in rpc_client.cr"
```

---

### Task 12: Rename JJFS to AgentFS in All Command Files

**Files:**
- Modify: `src/agent/fs/commands/*.cr` (all files)

**Step 1: Batch replace in all command files**

```bash
for file in src/agent/fs/commands/*.cr; do
  sed -i '' 's/module JJFS/module AgentFS/g' "$file"
  sed -i '' 's/JJFS::/AgentFS::/g' "$file"
done
```

**Step 2: List modified files**

```bash
git diff --name-only src/agent/fs/commands/
```

**Step 3: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | head -50
```

Expected: Should compile cleanly now or show only minor remaining issues

**Step 4: Commit**

```bash
git add src/agent/fs/commands/
git commit -m "Rename JJFS to AgentFS in all command files

Batch renamed module references in all fs command files."
```

---

### Task 13: Add Unix Socket RPC Server to Agent

**Files:**
- Modify: `src/agent.cr` (around line 56, add instance variable)
- Modify: `src/agent.cr` (in initialize method)
- Modify: `src/agent.cr` (in start method)
- Modify: `src/agent.cr` (in stop method)

**Step 1: Add instance variable for RPC server**

In `src/agent.cr`, after line 63 (`@x25519_shared_secret : Bytes?`), add:

```crystal
@rpc_server : AgentFS::RPCServer?
```

**Step 2: Initialize RPC server in start method**

In the `start` method, after line 415 (`start_ping_loop`), add:

```crystal
# Start Unix socket RPC server for fs commands
start_rpc_server
```

**Step 3: Add start_rpc_server method**

At the end of the class (before final `end`), add:

```crystal
private def start_rpc_server
  socket_path = AgentFS::Config::SOCKET_PATH

  # Clean up stale socket
  File.delete(socket_path) if File.exists?(socket_path)

  # Ensure parent directory exists
  Dir.mkdir_p(socket_path.parent)

  # Create and start RPC server
  @rpc_server = AgentFS::RPCServer.new(socket_path)

  spawn do
    @rpc_server.not_nil!.start
  rescue ex : Exception
    puts "RPC server error: #{ex.message}" unless @graceful_shutdown
  end

  puts "RPC server listening on #{socket_path}"
rescue ex : Exception
  puts "Failed to start RPC server: #{ex.message}"
end
```

**Step 4: Stop RPC server in stop method**

In the `stop` method, after line 335 (`@websocket.try(&.close)`), add:

```crystal
# Stop RPC server
@rpc_server.try(&.stop)
```

**Step 5: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | head -30
```

Expected: May show some errors if RPCServer needs adjustment - that's fine for now

**Step 6: Commit**

```bash
git add src/agent.cr
git commit -m "Add Unix socket RPC server to agent

Agent now listens on Unix socket for local fs commands alongside
WebSocket for server communication."
```

---

### Task 14: Add fs Subcommands to CLI

**Files:**
- Modify: `src/agent/cli.cr`

**Step 1: Read current CLI structure**

```bash
grep -n "def self.parse" src/agent/cli.cr
```

**Step 2: Add fs subcommand handling**

In `src/agent/cli.cr`, find the main command parser (likely in `parse` method). After the existing subcommands (run, auth, security, etc.), add:

```crystal
when "fs"
  handle_fs_command(args[1..])
when "open"
  # Shorthand for "fs open"
  handle_fs_open(args[1..])
when "close"
  # Shorthand for "fs close"
  handle_fs_close(args[1..])
when "status"
  # If no other status handler, delegate to fs
  handle_fs_status(args[1..])
```

**Step 3: Add fs command handler methods**

At the end of the CLI module, add:

```crystal
def self.handle_fs_command(args : Array(String))
  if args.empty?
    puts "Usage: agent fs <subcommand>"
    puts "Subcommands: init, open, close, list, status"
    exit 1
  end

  subcommand = args[0]

  case subcommand
  when "init"
    handle_fs_init(args[1..])
  when "open"
    handle_fs_open(args[1..])
  when "close"
    handle_fs_close(args[1..])
  when "list"
    handle_fs_list(args[1..])
  when "status"
    handle_fs_status(args[1..])
  else
    puts "Unknown fs subcommand: #{subcommand}"
    exit 1
  end
end

def self.handle_fs_init(args : Array(String))
  # TODO: Implement via RPC client
  puts "fs init - not yet implemented"
end

def self.handle_fs_open(args : Array(String))
  # TODO: Implement via RPC client
  puts "fs open - not yet implemented"
end

def self.handle_fs_close(args : Array(String))
  # TODO: Implement via RPC client
  puts "fs close - not yet implemented"
end

def self.handle_fs_list(args : Array(String))
  # TODO: Implement via RPC client
  puts "fs list - not yet implemented"
end

def self.handle_fs_status(args : Array(String))
  # TODO: Implement via RPC client
  puts "fs status - not yet implemented"
end
```

**Step 4: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen
```

Expected: Should compile cleanly

**Step 5: Test help output**

```bash
./agent fs
```

Expected: Shows usage message

**Step 6: Commit**

```bash
git add src/agent/cli.cr
git commit -m "Add fs subcommands to CLI

Added agent fs, agent open, agent close, agent status commands.
Stubs for now - will implement via RPC client next."
```

---

### Task 15: Implement RPC Client for CLI Commands

**Files:**
- Modify: `src/agent/cli.cr` (replace TODO stubs)

**Step 1: Add RPC client usage in handle_fs_open**

Replace the `handle_fs_open` stub with:

```crystal
def self.handle_fs_open(args : Array(String))
  if args.empty?
    puts "Usage: agent open [repo] <path>"
    puts "Examples:"
    puts "  agent open .                    # Mount default share in current dir"
    puts "  agent open ~/Documents/notes    # Mount default share at path"
    puts "  agent open acme/shared .        # Mount specific repo"
    exit 1
  end

  # Parse arguments
  repo_name = nil
  mount_path = nil

  if args.size == 1
    # agent open <path> - use default repo
    mount_path = args[0]
  elsif args.size == 2
    # agent open <repo> <path>
    repo_name = args[0]
    mount_path = args[1]
  else
    puts "Error: Too many arguments"
    exit 1
  end

  # Expand path
  mount_path = File.expand_path(mount_path)

  # Connect to RPC server and send command
  begin
    client = AgentFS::RPCClient.new
    result = client.call("fs.open", {
      "repo" => repo_name,
      "path" => mount_path
    })

    if result["success"]?
      puts "✅ Mounted #{repo_name || "default"} at #{mount_path}"
    else
      puts "❌ Error: #{result["error"]?}"
      exit 1
    end
  rescue ex : Exception
    puts "❌ Failed to connect to agent: #{ex.message}"
    puts "Is the agent running? Try: agent run"
    exit 1
  end
end
```

**Step 2: Implement handle_fs_close**

Replace the stub with:

```crystal
def self.handle_fs_close(args : Array(String))
  if args.empty?
    puts "Usage: agent close <path>"
    puts "Example: agent close ~/Documents/notes"
    exit 1
  end

  mount_path = File.expand_path(args[0])

  begin
    client = AgentFS::RPCClient.new
    result = client.call("fs.close", {"path" => mount_path})

    if result["success"]?
      puts "✅ Unmounted #{mount_path}"
    else
      puts "❌ Error: #{result["error"]?}"
      exit 1
    end
  rescue ex : Exception
    puts "❌ Failed to connect to agent: #{ex.message}"
    exit 1
  end
end
```

**Step 3: Implement handle_fs_list**

Replace the stub with:

```crystal
def self.handle_fs_list(args : Array(String))
  begin
    client = AgentFS::RPCClient.new
    result = client.call("fs.list", {} of String => String)

    if repos = result["repos"]?.try(&.as_a?)
      if repos.empty?
        puts "No repositories configured"
      else
        puts "Repositories:"
        repos.each do |repo|
          puts "  #{repo["name"]?} (#{repo["path"]?})"
        end
      end
    else
      puts "❌ Error: #{result["error"]?}"
      exit 1
    end
  rescue ex : Exception
    puts "❌ Failed to connect to agent: #{ex.message}"
    exit 1
  end
end
```

**Step 4: Implement handle_fs_status**

Replace the stub with:

```crystal
def self.handle_fs_status(args : Array(String))
  begin
    client = AgentFS::RPCClient.new
    result = client.call("fs.status", {} of String => String)

    if mounts = result["mounts"]?.try(&.as_a?)
      if mounts.empty?
        puts "No active mounts"
      else
        puts "Active Mounts:"
        mounts.each do |mount|
          repo = mount["repo"]?
          path = mount["path"]?
          files = mount["file_count"]?
          puts "  #{repo} → #{path} (#{files} files)"
        end
      end
    else
      puts "❌ Error: #{result["error"]?}"
      exit 1
    end
  rescue ex : Exception
    puts "❌ Failed to connect to agent: #{ex.message}"
    exit 1
  end
end
```

**Step 5: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen
```

**Step 6: Commit**

```bash
git add src/agent/cli.cr
git commit -m "Implement RPC client for fs CLI commands

CLI commands now communicate with agent daemon via Unix socket."
```

---

### Task 16: Add get_default_share WebSocket Command

**Files:**
- Modify: `src/agent.cr` (in execute_command method)

**Step 1: Add command handler**

In `src/agent.cr`, find the `execute_command` method (around line 615). After the existing `when` clauses, before the `else`, add:

```crystal
when "get_default_share"
  # Return configured default share info
  # For now, return a placeholder - server will need to provide this
  {
    "org_slug" => "default",
    "git_url" => "", # Server should provide this
    "name" => "shared"
  }
```

**Step 2: Add to available tools list**

Find the `get_available_tools` method (around line 1039), add to the array:

```crystal
"get_default_share",
```

**Step 3: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen
```

**Step 4: Commit**

```bash
git add src/agent.cr
git commit -m "Add get_default_share WebSocket command

Allows agent to query server for org's default repository.
Returns placeholder for now - server integration needed."
```

---

### Task 17: Implement Org-Scoped Repo Naming

**Files:**
- Modify: `src/agent/fs/commands/open.cr`

**Step 1: Add default repo resolution**

In `src/agent/fs/commands/open.cr`, find the command execution logic. Add logic to query for default if no repo specified:

```crystal
def execute(repo_name : String?, mount_path : String)
  # If no repo specified, get default from server
  if repo_name.nil?
    repo_name = get_default_repo_name
  end

  # Ensure repo exists locally
  ensure_repo_exists(repo_name)

  # Proceed with mount...
  # [existing mount logic]
end

private def get_default_repo_name : String
  # Query agent's websocket connection for default share
  # This will be implemented via agent's WebSocket query
  # For now, return hardcoded default
  "default/shared"
end

private def ensure_repo_exists(repo_name : String)
  repo_path = AgentFS::Config::BASE_DIR / "repos" / repo_name

  unless Dir.exists?(repo_path)
    # Repo doesn't exist - need to import from server
    import_default_repo(repo_name)
  end
end

private def import_default_repo(repo_name : String)
  # Query server for git URL
  # Clone using jj git clone
  # This requires server integration - stub for now
  raise "Repository #{repo_name} not found locally and server import not yet implemented"
end
```

**Step 2: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | head -30
```

**Step 3: Commit**

```bash
git add src/agent/fs/commands/open.cr
git commit -m "Add org-scoped repo naming to open command

Implements default repo resolution and ensures repo exists.
Server integration for importing default repo is stubbed."
```

---

### Task 18: Update Agent Startup to Initialize FS

**Files:**
- Modify: `src/agent.cr` (in start method)

**Step 1: Add FS initialization after RPC server start**

In the `start` method, after `start_rpc_server`, add:

```crystal
# Initialize filesystem mounts
initialize_fs
```

**Step 2: Add initialize_fs method**

Add new private method:

```crystal
private def initialize_fs
  # Ensure base directories exist
  base_dir = AgentFS::Config::BASE_DIR
  Dir.mkdir_p(base_dir / "repos")

  # Restore previous mounts from config
  AgentFS::MountManager.restore_mounts

  # Start sync coordinator
  AgentFS::SyncCoordinator.start

  puts "Filesystem mount manager initialized"
rescue ex : Exception
  puts "Warning: Failed to initialize filesystem mounts: #{ex.message}"
end
```

**Step 3: Verify compilation**

```bash
crystal build src/agent.cr --no-codegen 2>&1 | head -30
```

Expected: May have errors if MountManager/SyncCoordinator need adjustment

**Step 4: Commit**

```bash
git add src/agent.cr
git commit -m "Initialize filesystem mounts on agent startup

Agent now restores previous mounts and starts sync coordinator."
```

---

### Task 19: Build jjfs-nfs Rust Binary

**Files:**
- Create: `Makefile` or update existing build script
- Directory: `../../jjfs/jjfs-nfs/`

**Step 1: Build Rust NFS server**

```bash
cd ../../jjfs/jjfs-nfs
cargo build --release
cd -
```

**Step 2: Copy binary to agent directory**

```bash
mkdir -p bin
cp ../../jjfs/jjfs-nfs/target/release/jjfs-nfs bin/
```

**Step 3: Verify binary works**

```bash
./bin/jjfs-nfs --help
```

Expected: Shows NFS server help

**Step 4: Add to .gitignore**

Ensure `bin/jjfs-nfs` is in .gitignore (bin/ likely already ignored)

**Step 5: Commit**

```bash
git add bin/jjfs-nfs -f 2>/dev/null || echo "Binary ignored by .gitignore - that's fine"
git commit -m "Build and bundle jjfs-nfs binary

Compiled Rust NFS server for inclusion with agent." --allow-empty
```

---

### Task 20: Test Basic Compilation

**Files:**
- Test: Full agent binary

**Step 1: Build agent**

```bash
crystal build src/agent.cr -o agent
```

Expected: Builds successfully or shows remaining errors to fix

**Step 2: Check binary size**

```bash
ls -lh agent
```

**Step 3: Test help output**

```bash
./agent --help
```

**Step 4: Test fs help**

```bash
./agent fs
```

**Step 5: Document remaining issues**

If compilation failed, document errors:

```bash
crystal build src/agent.cr 2>&1 > build-errors.log
cat build-errors.log
```

Create a file `REMAINING_ISSUES.md` listing what needs to be fixed.

**Step 6: Commit**

```bash
git add REMAINING_ISSUES.md 2>/dev/null || true
git commit -m "Test basic compilation

Verified agent builds with fs integration.
[Document any remaining issues found]" --allow-empty
```

---

## Post-Implementation Verification

After completing all tasks, verify:

1. **Compilation:**
   ```bash
   crystal build src/agent.cr -o agent
   ```

2. **CLI works:**
   ```bash
   ./agent fs --help
   ./agent open --help
   ./agent close --help
   ```

3. **RPC server starts:**
   ```bash
   ./agent run # In one terminal
   # Verify socket exists
   ls -la ~/.config/gentility/agent.sock
   ```

4. **Basic command flow:**
   ```bash
   ./agent fs list  # Should connect to daemon
   ```

## Next Steps (Future PRs)

After this PR is merged:

1. **Server Integration**
   - Implement actual get_default_share query to server
   - Add git URL to default repo response
   - Implement auto-import of default repo

2. **Mount Implementation**
   - Wire up actual NFS server spawning
   - Implement sudo mount commands
   - Add mount restoration on startup

3. **Sync Implementation**
   - Implement file watching
   - Implement auto-commit on changes
   - Implement remote sync

4. **Testing**
   - Add spec tests for AgentFS modules
   - Integration tests for mount flow
   - End-to-end tests with real mounts

## Success Criteria

- [ ] All code compiles without errors
- [ ] Agent starts with RPC server listening
- [ ] CLI commands parse correctly
- [ ] fs subcommands recognized
- [ ] WebSocket command added
- [ ] All commits have descriptive messages
- [ ] No broken functionality in existing agent features
