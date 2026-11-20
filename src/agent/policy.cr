# Which commands this agent will run at all, decided by the operator of the
# host and never by the server.
#
# `full` (the default) is the historical behaviour: every command, each still
# subject to the lock (`security:`) where it applies.
#
# `database` is for an agent whose only job is to run SQL against databases
# its network can reach, e.g. one deployed inside a customer's cluster. It
# refuses shell execution, file access, gateway installs and remote changes to
# its own security settings, and it never becomes an egress route. The server
# cannot widen it: the mode comes from the config file and the environment
# only, and no command changes it.
module AgentPolicy
  FULL     = "full"
  DATABASE = "database"
  MODES    = [FULL, DATABASE]

  ENV_VAR    = "GENTILITY_MODE"
  CONFIG_KEY = "agent_mode"

  # Everything a database-only agent answers. An allow-list, so a command
  # added to the agent later stays off here until someone decides otherwise.
  DATABASE_COMMANDS = Set{
    "ping",
    "system_info",
    "check_capabilities",
    "get_status",
    "psql_query",
    "mysql_query",
    "psql_query_encrypted",
    "mysql_query_encrypted",
    "store_credentials",
    "secure_psql_query",
    "secure_mysql_query",
    "security_unlock",
    "security_lock",
    "ecdh_test",
  }

  class InvalidMode < Exception
  end

  # The mode from the config file's `agent_mode` and from GENTILITY_MODE.
  # Either one asking for `database` wins, so an environment variable can
  # tighten a host but never loosen what its config file restricts. A value
  # that is not a known mode raises: a typo must not fall back to `full`.
  def self.resolve(config : YAML::Any?, env_value : String? = ENV[ENV_VAR]?) : String
    from_config = config.try(&.as_h?).try(&.[YAML::Any.new(CONFIG_KEY)]?).try(&.as_s?)
    requested = [
      {"#{CONFIG_KEY} in the config file", from_config},
      {ENV_VAR, env_value},
    ].compact_map do |(source, value)|
      next nil if value.nil? || value.strip.empty?
      mode = value.strip.downcase
      unless MODES.includes?(mode)
        raise InvalidMode.new("Unknown agent mode #{value.inspect} from #{source}. Use one of: #{MODES.join(", ")}")
      end
      mode
    end

    requested.includes?(DATABASE) ? DATABASE : FULL
  end

  def self.allows?(mode : String, command : String) : Bool
    mode == FULL || DATABASE_COMMANDS.includes?(command)
  end

  def self.allows_egress?(mode : String) : Bool
    mode == FULL
  end

  def self.filter_tools(mode : String, tools : Array(String)) : Array(String)
    tools.select { |tool| allows?(mode, tool) }
  end
end
