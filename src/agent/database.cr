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
      # Use psql with environment variable to avoid password prompt.
      # `-A --csv` emits a header row followed by RFC-4180 CSV; we parse it
      # into both a `columns` list and a list-of-list `rows`. The header row
      # is what the Elixir side needs to apply column-aware redaction.
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")

      psql_cmd = "PGPASSWORD='#{password || ""}' psql -h #{host} -p #{port}"
      psql_cmd += " -U #{username}" if username
      psql_cmd += " -d #{dbname} -A --csv -c \"#{escaped_query}\""

      execute_db_command(psql_cmd, :csv, "PostgreSQL")
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
      # `--batch --raw` emits tab-separated output. We deliberately omit
      # `--skip-column-names` so the first line is the header row, which
      # we use to populate `columns` for the Elixir redaction layer.
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")
      mysql_cmd = "mysql -h #{host} -P #{port} -D #{dbname} --batch --raw -e \"#{escaped_query}\""

      execute_db_command(mysql_cmd, :tsv, "MySQL")
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

  # Execute database command and parse results.
  # `format` is `:csv` (RFC-4180 with quoted fields) or `:tsv` (tab-delimited).
  private def self.execute_db_command(command : String, format : Symbol, db_type : String)
    # Note: command logged at debug level only - may contain credentials in env vars
    Log.debug { "Executing DB command for #{db_type}" }

    process = Process.new(
      command,
      shell: true,
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
