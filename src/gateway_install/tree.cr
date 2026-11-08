module GatewayInstaller
  # Who owns a file, and its mode. `uid`/`gid` of UInt32::MAX leave the owner
  # as created, which is root when the helper runs.
  record Owner, uid : UInt32, gid : UInt32, mode : Int32 do
    def self.root(mode : Int32) : Owner
      new(UInt32::MAX, UInt32::MAX, mode)
    end
  end

  # The host's files, reached from a root without following a symlink at any
  # step. The proxy's user owns /var/lib/cliproxyapi, so anything there may be a
  # link it planted; walking with O_NOFOLLOW, writing a fresh O_EXCL temp file
  # and renaming it over the target keeps root's reads and writes on the path
  # named, never wherever a link points.
  class Tree
    lib C
      fun openat(dirfd : LibC::Int, path : LibC::Char*, flags : LibC::Int, ...) : LibC::Int
      fun renameat(fromfd : LibC::Int, from : LibC::Char*, tofd : LibC::Int, to : LibC::Char*) : LibC::Int
      fun unlinkat(dirfd : LibC::Int, path : LibC::Char*, flags : LibC::Int) : LibC::Int
      fun mkdirat(dirfd : LibC::Int, path : LibC::Char*, mode : LibC::ModeT) : LibC::Int
    end

    {% if flag?(:darwin) %}
      O_DIRECTORY = 0x100000
    {% elsif flag?(:aarch64) %}
      O_DIRECTORY = 0o40000
    {% else %}
      O_DIRECTORY = 0o200000
    {% end %}
    NOFOLLOW = LibC::O_NOFOLLOW | LibC::O_CLOEXEC

    def initialize(@root : String)
    end

    # Yields the file's contents, or nil when there is none. Refuses a link,
    # anything but a regular file, and a file with other names (a hard link).
    def read(path : String, & : IO::FileDescriptor? -> T) : T forall T
      dirfd = open_dir(File.dirname(path))
      return yield nil unless dirfd
      begin
        fd = C.openat(dirfd, File.basename(path), LibC::O_RDONLY | LibC::O_NONBLOCK | NOFOLLOW)
        return yield nil if fd < 0 && Errno.value.enoent?
        raise RuntimeError.from_errno("Cannot open #{path}") if fd < 0
        io = IO::FileDescriptor.new(fd)
        begin
          stat = stat(fd, path)
          raise "#{path} is not a regular file" unless stat.st_mode & LibC::S_IFMT == LibC::S_IFREG
          raise "#{path} has other names" unless stat.st_nlink == 1
          yield io
        ensure
          io.close
        end
      ensure
        LibC.close(dirfd)
      end
    end

    def read(path : String) : String?
      read(path, &.try(&.gets_to_end))
    end

    def owner(path : String) : Owner?
      read(path) { |io| owner(io, path) if io }
    end

    def exists?(path : String) : Bool
      read(path) { |io| !io.nil? }
    end

    # Copies a file with its owner and mode, or another `owner`; false when
    # there is no file to copy.
    def copy(from : String, to : String, owner : Owner? = nil) : Bool
      read(from) do |io|
        next false unless io
        write(to, io, owner || owner(io, from))
        true
      end
    end

    # Writes the file whole, through a rename, so it is never half written.
    def write(path : String, content : String | IO, owner : Owner) : Nil
      dirfd = open_dir(File.dirname(path), create: true).not_nil!
      temp = ".#{File.basename(path)}.#{Random::Secure.hex(8)}"
      fd = C.openat(dirfd, temp, LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL | NOFOLLOW, 0o600)
      raise RuntimeError.from_errno("Cannot create #{path}") if fd < 0
      io = IO::FileDescriptor.new(fd)
      begin
        content.is_a?(String) ? io.print(content) : IO.copy(content, io)
        io.flush
        check LibC.fchown(fd, owner.uid, owner.gid), path
        check LibC.fchmod(fd, LibC::ModeT.new(owner.mode)), path
        io.fsync
        io.close
        check C.renameat(dirfd, temp, dirfd, File.basename(path)), path
        LibC.fsync(dirfd)
      rescue ex
        io.close
        C.unlinkat(dirfd, temp, 0)
        raise ex
      ensure
        LibC.close(dirfd)
      end
    end

    def delete(path : String) : Nil
      return unless dirfd = open_dir(File.dirname(path))
      if C.unlinkat(dirfd, File.basename(path), 0) < 0 && !Errno.value.enoent?
        raise RuntimeError.from_errno("Cannot delete #{path}")
      end
    ensure
      LibC.close(dirfd) if dirfd
    end

    # Opens each step of `path` below the root as a directory, never a link,
    # making the missing ones when `create`; nil when one is missing otherwise.
    private def open_dir(path : String, create = false) : LibC::Int?
      fd = LibC.open(@root.empty? ? "/" : @root, LibC::O_RDONLY | O_DIRECTORY | LibC::O_CLOEXEC)
      raise RuntimeError.from_errno("Cannot open #{@root}") if fd < 0
      path.split('/', remove_empty: true).each do |step|
        next_fd = C.openat(fd, step, LibC::O_RDONLY | O_DIRECTORY | NOFOLLOW)
        if next_fd < 0 && Errno.value.enoent? && create
          C.mkdirat(fd, step, 0o755)
          next_fd = C.openat(fd, step, LibC::O_RDONLY | O_DIRECTORY | NOFOLLOW)
        end
        if next_fd < 0
          error = RuntimeError.from_errno("Cannot open #{path} (at #{step})")
          missing = Errno.value.enoent?
          LibC.close(fd)
          return if missing
          raise error
        end
        LibC.close(fd)
        fd = next_fd
      end
      fd
    end

    private def owner(io : IO::FileDescriptor, path : String) : Owner
      stat = stat(io.fd, path)
      Owner.new(stat.st_uid.to_u32, stat.st_gid.to_u32, (stat.st_mode & 0o7777).to_i32)
    end

    private def stat(fd : LibC::Int, path : String) : LibC::Stat
      check LibC.fstat(fd, out stat), path
      stat
    end

    private def check(result : LibC::Int, path : String) : Nil
      raise RuntimeError.from_errno("Cannot write #{path}") if result < 0
    end
  end
end
