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

    # No file the helper reads or copies is larger than this.
    MAX_FILE = 512_i64 * 1024 * 1024

    def initialize(@root : String)
    end

    # Yields the file's contents, as of its size when opened, with its owner
    # and mode; or nils when there is no file. Refuses a link, anything but a
    # regular file, a file with other names (a hard link), and one over `max`.
    def read(path : String, max = MAX_FILE, & : IO?, Owner? -> T) : T forall T
      dirfd = open_dir(File.dirname(path))
      return yield nil, nil unless dirfd
      begin
        fd = C.openat(dirfd, step(File.basename(path)), LibC::O_RDONLY | LibC::O_NONBLOCK | NOFOLLOW)
        return yield nil, nil if fd < 0 && Errno.value.enoent?
        check fd, "open", path
        io = IO::FileDescriptor.new(fd)
        begin
          check LibC.fstat(fd, out stat), "stat", path
          raise "#{path} is not a regular file" unless stat.st_mode & LibC::S_IFMT == LibC::S_IFREG
          raise "#{path} has other names" unless stat.st_nlink == 1
          raise "#{path} is larger than #{max} bytes" if stat.st_size > max
          owner = Owner.new(stat.st_uid.to_u32, stat.st_gid.to_u32, (stat.st_mode & 0o777).to_i32)
          yield IO::Sized.new(io, stat.st_size), owner
        ensure
          io.close
        end
      ensure
        LibC.close(dirfd)
      end
    end

    def read(path : String, max = MAX_FILE) : String?
      read(path, max) { |io, _| io.try(&.gets_to_end) }
    end

    def owner(path : String) : Owner?
      read(path) { |_, owner| owner }
    end

    def exists?(path : String) : Bool
      read(path) { |io, _| !io.nil? }
    end

    # Copies a file with its owner and mode; false when there is no file.
    def copy(from : String, to : String, max = MAX_FILE) : Bool
      read(from, max) do |io, owner|
        next false unless io && owner
        write(to, io, owner)
        true
      end
    end

    # Writes the file whole, through a rename, so it is never half written.
    def write(path : String, content : String | IO, owner : Owner) : Nil
      name = step(File.basename(path))
      dirfd = open_dir(File.dirname(path), create: true).not_nil!
      temp = ".#{name}.#{Random::Secure.hex(8)}"
      fd = C.openat(dirfd, temp, LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL | NOFOLLOW, 0o600)
      begin
        check fd, "create", path
      rescue ex
        LibC.close(dirfd)
        raise ex
      end
      io = IO::FileDescriptor.new(fd)
      begin
        content.is_a?(String) ? io.print(content) : IO.copy(content, io)
        io.flush
        check LibC.fchown(fd, owner.uid, owner.gid), "chown", path
        check LibC.fchmod(fd, LibC::ModeT.new(owner.mode)), "chmod", path
        io.fsync
        io.close
        check C.renameat(dirfd, temp, dirfd, name), "rename", path
        check LibC.fsync(dirfd), "sync the directory of", path
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
      if C.unlinkat(dirfd, step(File.basename(path)), 0) < 0 && !Errno.value.enoent?
        check -1, "delete", path
      end
    ensure
      LibC.close(dirfd) if dirfd
    end

    # Opens each step of `path` below the root as a directory, never a link,
    # making the missing ones when `create`; nil when one is missing otherwise.
    private def open_dir(path : String, create = false) : LibC::Int?
      fd = LibC.open(@root.empty? ? "/" : @root, LibC::O_RDONLY | O_DIRECTORY | LibC::O_CLOEXEC)
      check fd, "open", @root
      path.split('/', remove_empty: true).each do |name|
        next_fd = C.openat(fd, step(name), LibC::O_RDONLY | O_DIRECTORY | NOFOLLOW)
        if next_fd < 0 && Errno.value.enoent? && create
          if C.mkdirat(fd, name, 0o755) < 0 && !Errno.value.eexist?
            errno = Errno.value
            LibC.close(fd)
            raise RuntimeError.from_os_error("Cannot make #{path} (at #{name})", errno)
          end
          next_fd = C.openat(fd, name, LibC::O_RDONLY | O_DIRECTORY | NOFOLLOW)
        end
        if next_fd < 0
          errno = Errno.value
          LibC.close(fd)
          return if errno.enoent?
          raise RuntimeError.from_os_error("Cannot open #{path} (at #{name})", errno)
        end
        LibC.close(fd)
        fd = next_fd
      end
      fd
    end

    private def step(name : String) : String
      raise "#{name.inspect} is not a file name" if name.in?("", ".", "..") || name.includes?('/')
      name
    end

    private def check(result : LibC::Int, what : String, path : String) : Nil
      return unless result < 0
      errno = Errno.value
      raise RuntimeError.from_os_error("Cannot #{what} #{path}", errno)
    end
  end
end
