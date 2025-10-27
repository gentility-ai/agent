require "process"

module AgentDatabase
  # Execute PostgreSQL query
  def self.execute_psql_query(host : String, port : Int32, dbname : String, query : String, username : String?, password : String?)
    puts "Executing PostgreSQL query on #{host}:#{port}/#{dbname}"
    puts "Query: #{query}"

    begin
      # Use psql with environment variable to avoid password prompt
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")

      # Build the psql command with proper authentication
      psql_cmd = "PGPASSWORD='#{password || ""}' psql -h #{host} -p #{port}"
      psql_cmd += " -U #{username}" if username
      psql_cmd += " -d #{dbname} -t -A -c \"#{escaped_query}\""

      execute_db_command(psql_cmd, "|", "PostgreSQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute PostgreSQL query: #{ex.message}",
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  # Execute MySQL query
  def self.execute_mysql_query(host : String, port : Int32, dbname : String, query : String)
    puts "Executing MySQL query on #{host}:#{port}/#{dbname}"
    puts "Query: #{query}"

    begin
      # Use mysql with batch mode to avoid password prompt
      escaped_query = query.gsub("\"", "\\\"").gsub("`", "\\`").gsub("$", "\\$")
      mysql_cmd = "mysql -h #{host} -P #{port} -D #{dbname} --batch --raw --skip-column-names -e \"#{escaped_query}\""

      execute_db_command(mysql_cmd, "\t", "MySQL")
    rescue ex : Exception
      {
        "success"   => false,
        "error"     => "Failed to execute MySQL query: #{ex.message}",
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end

  # Execute database command and parse results
  private def self.execute_db_command(command : String, delimiter : String, db_type : String)
    puts "Executing: #{command}" if CLI.debug_mode

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
      # Parse the output into rows
      rows = if stdout.strip.empty?
               [] of Array(String)
             else
               stdout.strip.split("\n").map do |line|
                 line.split(delimiter).map(&.strip)
               end
             end

      {
        "success"   => true,
        "rows"      => rows,
        "row_count" => rows.size,
      }
    else
      error_message = stderr.empty? ? "Query failed" : stderr.strip

      # Provide helpful authentication error messages
      if error_message.includes?("authentication") || error_message.includes?("Access denied")
        error_message = "#{db_type} authentication required. Please configure credentials on the agent server."
      end

      {
        "success"   => false,
        "error"     => error_message,
        "rows"      => [] of Array(String),
        "row_count" => 0,
      }
    end
  end
end
