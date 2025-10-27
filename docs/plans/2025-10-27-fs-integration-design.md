# Filesystem Mount Integration Design

**Date:** 2025-10-27
**Status:** Approved for Implementation

## Overview

Integrate jjfs functionality into the Gentility agent to provide unified filesystem mount management. The agent will manage local file mounts that sync both locally (between workspaces) and remotely (to git servers), eliminating the need for a separate daemon.

## Goals

1. **Single daemon process** - Agent handles both server communication and file mounts
2. **Simple UX** - `agent open .` mounts org-scoped default share in current directory
3. **Server integration** - Server provides default repos per organization
4. **Auto-sync** - Changes propagate between mounts and to git remotes automatically
5. **Lift and shift** - Migrate jjfs code with minimal changes

## Architecture

### High-Level Components

```
agent (unified daemon)
├── WebSocket Handler (existing)
│   ├── Server commands → execute_command()
│   └── New: get_default_share query
├── Unix Socket RPC Handler (new)
│   └── fs commands → execute_fs_command()
├── Mount Manager (from jjfs)
│   ├── NFS Server Manager
│   └── Mount/Unmount operations
└── Sync Coordinator (from jjfs)
    ├── File Watcher (fswatch/inotify)
    └── Remote Syncer (git push/pull)

jjfs-nfs (Rust, separate processes)
└── One process per mount
```

### Dual Communication Channels

**1. WebSocket (existing) - Server ↔ Agent**
- Existing commands: execute, file_read, psql_query, etc.
- New command: `get_default_share` - Returns org's default repo URL

**2. Unix Socket (new) - Local CLI ↔ Agent**
- Protocol: JSON-RPC 2.0
- Socket: `~/.config/gentility/agent.sock` (user) or `/run/gentility/agent.sock` (system)
- Commands: fs operations (open, close, status, list, init)

## Directory Structure

### Source Code

```
src/agent/
├── agent.cr (existing - add RPC server)
├── cli.cr (existing - add fs subcommands)
├── config.cr (existing)
├── security.cr (existing)
├── crypto.cr (existing)
├── database.cr (existing)
├── oauth.cr (existing)
└── fs/ (new - jjfs code migrated here)
    ├── config.cr
    ├── storage.cr
    ├── mount_manager.cr
    ├── nfs_server.cr
    ├── sync_coordinator.cr
    ├── watcher.cr
    ├── remote_syncer.cr
    ├── rpc_server.cr (modified)
    ├── rpc_client.cr
    └── commands/
        ├── init.cr
        ├── open.cr
        ├── close.cr
        ├── list.cr
        └── status.cr
```

### Configuration & Data Paths

**User Mode:**
```
~/.config/gentility/
├── agent.yml              (existing)
├── credentials.enc        (existing)
├── agent.sock             (Unix socket)
├── fs/
│   ├── config.json        (mount configuration)
│   └── repos/             (jj repositories)
│       └── <org>/<repo>/
│           └── workspaces/
└── nfs/                   (NFS server binaries)
```

**System Mode:**
```
/etc/gentility/
└── agent.yml              (existing)

/var/lib/gentility/
├── credentials.enc
├── fs/
│   ├── config.json
│   └── repos/

/run/gentility/
└── agent.sock
```

## Repository Naming & Organization

### Org-Scoped Defaults

Repositories are namespaced by organization slug:

- **Org default:** `acme/shared` - Organization-wide shared context
- **User default:** `acme/username` - User's personal context
- **Future expansion:** `acme/team1`, `acme/team2` - Team-specific contexts

### Default Share Flow

```
User runs: agent open .

1. CLI sends RPC to agent via Unix socket
2. Agent checks if org default repo exists (e.g., "acme/shared")
3. If not found:
   a. Agent queries server via WebSocket: "get_default_share"
   b. Server responds: {
        "org_slug": "acme",
        "git_url": "git@github.com:acme/shared-context.git"
      }
   c. Agent imports as "acme/shared": jj git clone <url>
4. Agent mounts repo at requested path
5. Future "agent open" commands use cached repo
```

## Command Interface

### Simplified User Commands

```bash
# Simple mounting (uses org default: org_slug/shared)
agent open .                           # Mount org default in current dir
agent open ~/Documents/notes           # Mount org default at path

# Explicit repo
agent open acme/shared .               # Mount specific repo
agent open acme/username ~/my-context  # Mount user's personal repo

# Unmounting
agent close .                          # Unmount current dir
agent close ~/path                     # Unmount specific path

# Status
agent status                           # Show all mounts

# Minimal repo management
agent fs list                          # List all local repos
agent fs init acme/myrepo              # Create new local repo
```

### Example Output

```
$ agent status

Repositories:
  acme/shared (2 mounts, 15 files, last sync: 2 mins ago)
    → ~/Documents/notes
    → ~/Projects/context
    Remote: git@github.com:acme/shared-context.git

  acme/james (1 mount, 42 files, last sync: 5 mins ago)
    → ~/work/notes
    Remote: git@github.com:acme/james-context.git
```

## Mount Management

### NFS Server per Mount

Each mount spawns a dedicated NFS server process:

```
agent open acme/shared ~/Documents/notes

1. AgentFS::MountManager receives request
2. Creates workspace: ~/.config/gentility/fs/repos/acme/shared/workspaces/<uuid>
3. Finds available port (e.g., 12345)
4. Spawns NFS server:
   Process.new("jjfs-nfs", ["--port", "12345", workspace_path])
5. Waits for server readiness
6. System mount:
   macOS: sudo mount_nfs -o port=12345,mountport=12345 localhost:/ ~/Documents/notes
   Linux: sudo mount -t nfs -o port=12345,mountport=12345 localhost:/ ~/Documents/notes
7. Saves to config.json
```

### Requirements

- **Sudo access:** Required for mount operations
  - Passwordless sudo preferred
  - Fail with helpful error if unavailable
- **One process per mount:** Proven pattern from jjfs
- **Port allocation:** Find available port dynamically

## Synchronization

### Local Sync (Between Workspaces)

When file changes detected in a mount:

1. **Auto-commit:** `jj commit -m "Auto-sync: <timestamp>"`
2. **Update workspaces:** `jj workspace update-stale`
3. All mounts of same repo reflect changes within ~2 seconds

### File Watching

- **macOS:** fswatch via Process
- **Linux:** inotify via Crystal bindings or fswatch
- **Debouncing:** 500ms window for rapid changes
- **One watcher per repo:** Not per mount

### Remote Sync

- `AgentFS::RemoteSyncer` periodically pushes to git remotes
- Default interval: 5 minutes (configurable)
- Server manages remote URLs (not exposed via CLI)

## Error Handling & Recovery

### Mount Failures

- NFS server fails → Clean up workspace, return error
- Mount command fails → Kill NFS server, return error
- Port in use → Find next available port, retry
- Already mounted → Return error with current location

### Crash Recovery

- **Agent restart:** Restore mounts from config.json
- **Stale mounts:** Unmount and clean up, or re-establish
- **Dead NFS process:** Detect via monitoring, restart or mark failed
- **Orphaned processes:** Adopt or kill on startup

### Lock Files

- Prevent concurrent operations on same repo
- Location: `~/.config/gentility/fs/repos/<org>/<repo>/.lock`
- Cleanup stale locks on startup

### Graceful Shutdown

On agent stop:
- **Mounts:** Leave mounted (persist across restarts)
- **NFS servers:** Leave running (owned by init/launchd)
- **Sync:** Stop watching, flush pending syncs

## Module Naming

Rename all jjfs modules to agent namespace:

- `JJFS::*` → `AgentFS::*`
- `JJFS::MountManager` → `AgentFS::MountManager`
- `JJFS::SyncCoordinator` → `AgentFS::SyncCoordinator`
- etc.

## Agent Startup Sequence

Modified startup with fs integration:

```crystal
def start
  # Existing: Connect to server via WebSocket
  connect_to_server

  # New: Start Unix socket RPC server
  start_rpc_server  # Listen on ~/.config/gentility/agent.sock

  # New: Restore previous mounts from config
  AgentFS::MountManager.restore_mounts

  # New: Start sync coordinator
  AgentFS::SyncCoordinator.start

  # Keep running...
  event_loop
end
```

## WebSocket Command Additions

### New Command: get_default_share

**Request:**
```json
{
  "type": "command",
  "command": "get_default_share",
  "request_id": "abc123"
}
```

**Response:**
```json
{
  "type": "response",
  "request_id": "abc123",
  "result": {
    "org_slug": "acme",
    "git_url": "git@github.com:acme/shared-context.git",
    "name": "shared"
  }
}
```

## Out of Scope

The following jjfs features are **not** migrated:

- `agent fs remote add/remove/push/pull` - Server manages remotes
- Manual git operations - Handled by server/auto-sync
- `install` command - Agent installation is separate

## Dependencies

### Required

- **Jujutsu (`jj`)** - Version control for workspaces
- **Sudo access** - For NFS mounts (or passwordless sudo config)
- **Rust toolchain** - To build jjfs-nfs

### Platform-Specific

- **macOS:** fswatch for file watching
- **Linux:** inotify support (kernel feature)

## Migration Path

1. Copy jjfs code to `src/agent/fs/`
2. Rename modules: `JJFS::*` → `AgentFS::*`
3. Update paths: `~/.jjfs/` → `~/.config/gentility/fs/`
4. Add Unix socket RPC server to agent
5. Add fs subcommands to CLI
6. Add `get_default_share` WebSocket command
7. Implement org-scoped repo naming
8. Test mount/unmount/sync workflows
9. Build and bundle jjfs-nfs with agent

## Success Criteria

- [ ] `agent open .` mounts org default share
- [ ] Changes sync between mounts within 2 seconds
- [ ] Mounts persist across agent restarts
- [ ] Org-scoped repos work correctly (`acme/shared`, `acme/username`)
- [ ] Unix socket RPC handles concurrent CLI commands
- [ ] NFS servers spawn/die cleanly per mount
- [ ] Works on both macOS and Linux
- [ ] Works in both user mode and system mode
