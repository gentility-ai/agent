require "process"
require "log"
require "csv"

module AgentDatabase
  Log = ::Log.for(self)

  # Execute PostgreSQL query
  def self.execute_psql_query(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?)
    Log.info { "PostgreSQL query request - #{host}:#{port}/#{dbname}" }
    Log.debug { "Query: #{query}" }

    begin
      args, env = psql_invocation(host, port, dbname, query, username, password)
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
  def self.execute_mysql_query(host : String, port : Int32, dbname : String, query : String)
    Log.info { "MySQL query request - #{host}:#{port}/#{dbname}" }
    Log.debug { "Query: #{query}" }

    begin
      execute_db_command("mysql", mysql_args(host, port, dbname, query), {} of String => String, :tsv, "MySQL")
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
  # `-A --csv` emits a header row followed by RFC-4180 CSV; we parse it into
  # both a `columns` list and a list-of-list `rows`. The header row is what
  # the Elixir side needs to apply column-aware redaction.
  def self.psql_invocation(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?) : Tuple(Array(String), Hash(String, String))
    args = ["-h", host, "-p", port.to_s]
    args << "-U" << username if username
    args << "-d" << dbname << "-A" << "--csv" << "-c" << query

    env = {} of String => String
    env["PGPASSWORD"] = password if password
    {args, env}
  end

  # `--batch --raw` emits tab-separated output. We deliberately omit
  # `--skip-column-names` so the first line is the header row, which we use
  # to populate `columns` for the Elixir redaction layer.
  def self.mysql_args(host : String, port : Int32, dbname : String, query : String) : Array(String)
    ["-h", host, "-P", port.to_s, "-D", dbname, "--batch", "--raw", "-e", query]
  end

  # Execute database command and parse results. The program is run directly
  # (no shell). `format` is `:csv` (RFC-4180 with quoted fields) or `:tsv`
  # (tab-delimited).
  private def self.execute_db_command(program : String, args : Array(String), env : Hash(String, String), format : Symbol, db_type : String)
    Log.debug { "Executing DB command for #{db_type}" }

    process = Process.new(
      program,
      args,
      env: env,
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
