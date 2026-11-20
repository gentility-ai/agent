require "./spec_helper"

private def config(yaml : String) : YAML::Any
  YAML.parse(yaml)
end

private def with_mode_env(value : String?, &)
  previous = ENV[AgentPolicy::ENV_VAR]?
  if value
    ENV[AgentPolicy::ENV_VAR] = value
  else
    ENV.delete(AgentPolicy::ENV_VAR)
  end
  yield
ensure
  if previous
    ENV[AgentPolicy::ENV_VAR] = previous
  else
    ENV.delete(AgentPolicy::ENV_VAR)
  end
end

describe AgentPolicy do
  describe ".resolve" do
    it "defaults to full when nothing asks for a mode" do
      AgentPolicy.resolve(nil, nil).should eq "full"
      AgentPolicy.resolve(config("nickname: box"), nil).should eq "full"
      AgentPolicy.resolve(nil, "  ").should eq "full"
    end

    it "reads database mode from the config file" do
      AgentPolicy.resolve(config("agent_mode: database"), nil).should eq "database"
    end

    it "reads database mode from the environment" do
      AgentPolicy.resolve(nil, "database").should eq "database"
      AgentPolicy.resolve(nil, " Database ").should eq "database"
    end

    it "does not let the environment loosen a restricted config file" do
      AgentPolicy.resolve(config("agent_mode: database"), "full").should eq "database"
    end

    it "lets the environment tighten a full config file" do
      AgentPolicy.resolve(config("agent_mode: full"), "database").should eq "database"
    end

    it "refuses an unknown mode instead of falling back to full" do
      expect_raises(AgentPolicy::InvalidMode, /databse/) do
        AgentPolicy.resolve(nil, "databse")
      end
      expect_raises(AgentPolicy::InvalidMode, /agent_mode/) do
        AgentPolicy.resolve(config("agent_mode: db-only"), nil)
      end
    end
  end

  describe ".allows?" do
    it "allows every command in full mode" do
      %w[execute file_read file_write gateway_install psql_query anything_new].each do |command|
        AgentPolicy.allows?("full", command).should be_true
      end
    end

    it "allows the query commands in database mode" do
      %w[ping get_status psql_query mysql_query psql_query_encrypted secure_psql_query store_credentials].each do |command|
        AgentPolicy.allows?("database", command).should be_true
      end
    end

    it "refuses shell, file, gateway and remote security changes in database mode" do
      %w[execute file_read file_write gateway_install security_set security_unset security_export].each do |command|
        AgentPolicy.allows?("database", command).should be_false
      end
    end

    it "refuses a command it has never heard of in database mode" do
      AgentPolicy.allows?("database", "some_future_command").should be_false
    end
  end

  it "allows egress only in full mode" do
    AgentPolicy.allows_egress?("full").should be_true
    AgentPolicy.allows_egress?("database").should be_false
  end
end

describe "GentilityAgent in database mode" do
  before_each do
    Security.lock
    Security.configure("none", nil, nil, 1800, true, true, "password")
  end

  it "runs every command by default" do
    with_mode_env(nil) do
      agent, config_file, _ = create_test_agent
      begin
        agent.mode.should eq "full"
        result = agent.run_command("execute", JSON.parse(%({"command": "echo hello"})))
        result.to_json.should contain("hello")
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  it "refuses shell and file commands and leaves no side effect" do
    with_mode_env("database") do
      agent, config_file, _ = create_test_agent
      marker = "/tmp/gentility-policy-#{Random.rand(1_000_000)}"
      begin
        agent.mode.should eq "database"

        result = agent.run_command("execute", JSON.parse(%({"command": "touch #{marker}"})))
        JSON.parse(result.to_json)["code"].as_s.should eq "command_disabled"

        result = agent.run_command("file_write", JSON.parse(%({"path": "#{marker}", "content": "x"})))
        JSON.parse(result.to_json)["code"].as_s.should eq "command_disabled"

        result = agent.run_command("file_read", JSON.parse(%({"path": "#{config_file}"})))
        JSON.parse(result.to_json)["code"].as_s.should eq "command_disabled"
        result.to_json.should_not contain("access_key")

        File.exists?(marker).should be_false
      ensure
        File.delete(marker) if File.exists?(marker)
        cleanup_test_agent(config_file)
      end
    end
  end

  it "still answers ping" do
    with_mode_env("database") do
      agent, config_file, _ = create_test_agent
      begin
        JSON.parse(agent.run_command("ping", nil).to_json)["status"].as_s.should eq "pong"
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  it "reads the mode from the config file" do
    with_mode_env(nil) do
      agent, config_file, _ = create_test_agent
      begin
        File.write(config_file, File.read(config_file) + "agent_mode: database\n")
        restricted = GentilityAgent.new("test-token", "ws://localhost:9000", "test-agent", "test")
        restricted.mode.should eq "database"
      ensure
        cleanup_test_agent(config_file)
      end
    end
  end

  it "stops on an unknown mode" do
    with_mode_env("databse") do
      expect_raises(AgentPolicy::InvalidMode) { create_test_agent }
    end
  end
end

describe "AgentDatabase command construction" do
  it "passes a hostile query to psql as one argument" do
    query = %(SELECT '"; touch /tmp/pwned; echo "' AS x, $$a$$, `id`, $(id))
    args, env = AgentDatabase.psql_invocation("db.internal", 5432, "app", query, "reader", "p'w; id")

    args.should eq ["-h", "db.internal", "-p", "5432", "-U", "reader", "-d", "app", "-A", "--csv", "-c", query]
    env.should eq({"PGPASSWORD" => "p'w; id"})
  end

  it "omits the user and password when none are given" do
    args, env = AgentDatabase.psql_invocation("h", 5432, "d", "SELECT 1", nil, nil)
    args.should eq ["-h", "h", "-p", "5432", "-d", "d", "-A", "--csv", "-c", "SELECT 1"]
    env.empty?.should be_true
  end

  it "passes a hostile query to mysql as one argument" do
    query = %(SELECT "$(id)" -- `x`)
    AgentDatabase.mysql_args("h", 3306, "d", query).should eq ["-h", "h", "-P", "3306", "-D", "d", "--batch", "--raw", "-e", query]
  end

  it "makes the psql session read-only when the server asks" do
    args, env = AgentDatabase.psql_invocation("h", 5432, "d", "SELECT 1", "reader", "pw", read_only: true)
    args.should eq ["-h", "h", "-p", "5432", "-U", "reader", "-d", "d", "-A", "--csv", "-c", "SELECT 1"]
    env.should eq({"PGPASSWORD" => "pw", "PGOPTIONS" => "-c default_transaction_read_only=on"})
  end

  it "makes the mysql session read-only when the server asks" do
    AgentDatabase.mysql_args("h", 3306, "d", "SELECT 1", read_only: true).should eq [
      "-h", "h", "-P", "3306", "-D", "d", "--batch", "--raw",
      "--init-command=SET SESSION TRANSACTION READ ONLY", "-e", "SELECT 1",
    ]
  end

  it "does not run shell syntax smuggled through the host" do
    marker = "/tmp/gentility-inject-#{Random.rand(1_000_000)}"
    begin
      result = AgentDatabase.execute_psql_query("localhost; touch #{marker}", 1, "d", "SELECT 1", nil, nil)
      result["success"].should be_false
      File.exists?(marker).should be_false
    ensure
      File.delete(marker) if File.exists?(marker)
    end
  end
end
