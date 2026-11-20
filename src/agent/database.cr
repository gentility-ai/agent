require "process"
require "log"
require "csv"

module AgentDatabase
  Log = ::Log.for(self)

  # Execute PostgreSQL query
  def self.execute_psql_query(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?, read_only : Bool = false)
    Log.info { "PostgreSQL query request - #{host}:#{port}/#{dbname}" }
    Log.debug { "Query: #{query}" }

    begin
      args, env = psql_invocation(host, port, dbname, query, username, password, read_only)
      execute_db_command("psql", args, env, :csv, "PostgreSQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute PostgreSQL query: #{ex.message}",
        "columns"   => [] of String,
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  # Execute MySQL query
  #
  # In every mode, a mysql client with no switch to turn its own shell and
  # file commands off is not run: query access must never be a shell.
  def self.execute_mysql_query(host : String, port : Int32, dbname : String, query : String, read_only : Bool = false)
    Log.info { "MySQL query request - #{host}:#{port}/#{dbname}" }
    Log.debug { "Query: #{query}" }

    begin
      sandbox = mysql_sandbox_flag
      unless sandbox
        raise ArgumentError.new("this mysql client cannot turn off its own shell commands; install a MariaDB client (--sandbox) or MySQL 8.4.3 or later (--commands)")
      end
      execute_db_command("mysql", mysql_args(host, port, dbname, query, read_only, sandbox), {} of String => String, :tsv, "MySQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute MySQL query: #{ex.message}",
        "columns"   => [] of String,
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  # Arguments and environment for one psql run. Every value is its own argv
  # entry and the password travels in the environment, so nothing the server
  # sends is ever parsed by a shell.
  #
  # psql itself would still run a `-c` string that starts with a backslash as
  # a meta-command (`\! cmd` is a shell), and would read a dbname holding `=`
  # or a URI as a connection string that can override host and options. Both
  # are refused (ArgumentError). `-X` skips any psqlrc.
  #
  # `-A --csv` emits a header row followed by RFC-4180 CSV; we parse it into
  # both a `columns` list and a list-of-list `rows`. The header row is what
  # the Elixir side needs to apply column-aware redaction.
  #
  # `read_only` (the server's `read_only: true`, capver 5) starts every
  # transaction read-only, the setting the server's own Postgres pools connect
  # with. It stops an accidental single-statement write, not a query that
  # turns it off again: the server refuses SET, BEGIN and multi-statement SQL
  # on reads, and the database role is what makes a target read-only.
  def self.psql_invocation(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?, read_only : Bool = false) : Tuple(Array(String), Hash(String, String))
    raise ArgumentError.new("a query may not start with a psql meta-command") if query.lstrip.starts_with?('\\')
    raise ArgumentError.new("dbname must be a database name, not a connection string") if dbname.includes?('=') || dbname.includes?("://")

    args = ["-X", "-h", host, "-p", port.to_s]
    args << "-U" << username if username
    args << "-d" << dbname << "-A" << "--csv" << "-c" << query

    env = {} of String => String
    env["PGPASSWORD"] = password if password
    env["PGOPTIONS"] = "-c default_transaction_read_only=on" if read_only
    {args, env}
  end

  # `--batch --raw` emits tab-separated output. We deliberately omit
  # `--skip-column-names` so the first line is the header row, which we use
  # to populate `columns` for the Elixir redaction layer.
  #
  # The mysql client runs its own commands (`system`, `\!`, `source`)
  # anywhere in an `-e` string, so no filtering of the query can fence them.
  # `sandbox` is the client's switch that turns them off (see
  # mysql_sandbox_flag); `--local-infile=0` stops LOAD DATA LOCAL reading the
  # agent's files.
  #
  # `read_only` starts the session read-only, as the server's own MySQL pools
  # do. Like psql's, it stops an accidental write, not a query that undoes it.
  def self.mysql_args(host : String, port : Int32, dbname : String, query : String, read_only : Bool = false, sandbox : String? = nil) : Array(String)
    args = ["-h", host, "-P", port.to_s, "-D", dbname, "--batch", "--raw", "--local-infile=0"]
    args << sandbox if sandbox
    args << "--init-command=SET SESSION TRANSACTION READ ONLY" if read_only
    args << "-e" << query
  end

  @@mysql_sandbox_flag : String? = nil
  @@mysql_sandbox_checked = false

  # The installed client's switch for turning its own commands off, found
  # once from `mysql --help`, or nil when it has none.
  def self.mysql_sandbox_flag : String?
    unless @@mysql_sandbox_checked
      help = IO::Memory.new
      Process.run("mysql", ["--help"], env: child_env, clear_env: true, output: help, error: Process::Redirect::Close) rescue nil
      @@mysql_sandbox_flag = sandbox_flag_from_help(help.to_s)
      @@mysql_sandbox_checked = true
    end
    @@mysql_sandbox_flag
  end

  # MariaDB's client has --sandbox; Oracle's has --commands from 8.4.3/9.1.
  def self.sandbox_flag_from_help(help : String) : String?
    if help.matches?(/^\s*--sandbox\b/m)
      "--sandbox"
    elsif help.matches?(/^\s*--commands\b/m)
      "--commands=OFF"
    end
  end

  # The variables a database client may see: locale, paths, and its own
  # PG*/MYSQL* settings. Never the agent's own (GENTILITY_TOKEN and the rest).
  INHERITED_ENV = /\A(PATH|HOME|USER|LANG|TZ|TMPDIR|LC_[A-Z]+|PG[A-Z_]+|MYSQL_[A-Z_]+|SSL_CERT_(FILE|DIR))\z/

  def self.child_env(extra = {} of String => String) : Hash(String, String)
    ENV.to_h.select { |name, _| INHERITED_ENV.matches?(name) }.merge(extra)
  end

  # Execute database command and parse results. The program is run directly
  # (no shell), with only the environment child_env allows. `format` is
  # `:csv` (RFC-4180 with quoted fields) or `:tsv` (tab-delimited).
  private def self.execute_db_command(program : String, args : Array(String), env : Hash(String, String), format : Symbol, db_type : String)
    Log.debug { "Executing DB command for #{db_type}" }

    process = Process.new(
      program,
      args,
      env: child_env(env),
      clear_env: true,
      input: Process::Redirect::Close,
      output: Process::Redirect::Pipe,
      error: Process::Redirect::Pipe
    )

    stdout = process.output.gets_to_end
    stderr = process.error.gets_to_end
    exit_status = process.wait

    if exit_status.success?
      columns, rows = parse_output(stdout, format)

      Log.info { "#{db_type} query succeeded - #{rows.size} rows returned" }
      {
        "success"   => true,
        "columns"   => columns,
        "rows"      => rows,
        "row_count" => rows.size,
      }
    else
      error_message = stderr.empty? ? "Query failed" : stderr.strip

      # Provide helpful authentication error messages
      if error_message.includes?("authentication") || error_message.includes?("Access denied")
        error_message = "#{db_type} authentication required. Please configure credentials on the agent server."
      end

      Log.warn { "#{db_type} query failed: #{error_message}" }
      {
        "success"   => false,
        "error"     => error_message,
        "columns"   => [] of String,
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  # Parse stdout into {columns, rows}. The first line (when present) is the
  # header row. Returning columns separately lets the server side reattach
  # column names for redaction policies, regardless of transport.
  private def self.parse_output(stdout : String, format : Symbol) : Tuple(Array(String), Array(Array(String)))
    trimmed = stdout.strip
    return {[] of String, [] of Array(String)} if trimmed.empty?

    parsed =
      case format
      when :csv
        CSV.parse(trimmed)
      when :tsv
        trimmed.split("\n").map { |line| line.split("\t") }
      else
        raise "Unknown output format: #{format}"
      end

    return {[] of String, [] of Array(String)} if parsed.empty?

    headers = parsed.first.map(&.strip)
    body = parsed[1..]? || [] of Array(String)
    {headers, body}
  end
end
