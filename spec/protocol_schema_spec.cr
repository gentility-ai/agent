require "./spec_helper"
require "yaml"

# Lightweight protocol schema conformance tests.
#
# Loads the AsyncAPI spec from the server repo and verifies that messages
# the agent constructs include all required fields with correct types.
# This is not full JSON Schema validation — it's a sanity check that the
# agent and spec stay in sync.

SPEC_PATH = File.join(__DIR__, "..", "..", "root", "protocol", "agent-protocol.asyncapi.yaml")

module ProtocolHelper
  # Load and cache the spec
  @@schemas : Hash(String, YAML::Any)?

  def self.schemas : Hash(String, YAML::Any)
    @@schemas ||= begin
      yaml = YAML.parse(File.read(SPEC_PATH))
      raw = yaml["components"]["schemas"]
      hash = {} of String => YAML::Any
      raw.as_h.each { |k, v| hash[k.as_s] = v }
      hash
    end
  end

  # Get required fields for a payload schema
  def self.required_fields(schema_name : String) : Array(String)
    schema = schemas[schema_name]
    if req = schema["required"]?
      req.as_a.map(&.as_s)
    else
      [] of String
    end
  end

  # Get the const value for the type field
  def self.expected_type(schema_name : String) : String?
    schema = schemas[schema_name]
    if props = schema["properties"]?
      if type_prop = props["type"]?
        if const = type_prop["const"]?
          return const.as_s
        end
      end
    end
    nil
  end

  # Verify a message hash has all required fields
  def self.assert_required_fields(msg : Hash, schema_name : String)
    required = required_fields(schema_name)
    required.each do |field|
      msg.has_key?(field).should be_true,
        "Message missing required field '#{field}' for schema #{schema_name}. " \
        "Message keys: #{msg.keys}"
    end
  end

  # Verify the type field matches the expected const
  def self.assert_type_field(msg : Hash, schema_name : String)
    expected = expected_type(schema_name)
    if expected
      msg["type"].should eq(expected),
        "Expected type '#{expected}' for #{schema_name}, got '#{msg["type"]}'"
    end
  end

  # Combined check
  def self.assert_matches_schema(msg : Hash, schema_name : String)
    assert_type_field(msg, schema_name)
    assert_required_fields(msg, schema_name)
  end
end

describe "Protocol Schema Conformance" do
  before_each do
    Security.lock
    Security.configure("none", nil, nil, 1800, true, true, "password")
  end

  describe "agent → server messages" do
    it "command.response has required fields" do
      msg = {
        "type"       => "command.response",
        "v"          => 2,
        "request_id" => "req_abc123",
        "result"     => {"status" => "pong"},
      }
      ProtocolHelper.assert_matches_schema(msg, "CommandResponsePayload")
    end

    it "command.error has required fields" do
      msg = {
        "type"       => "command.error",
        "v"          => 2,
        "request_id" => "req_abc123",
        "error"      => "command_not_found",
      }
      ProtocolHelper.assert_matches_schema(msg, "CommandErrorPayload")
    end

    it "agent.status has required fields and correct type" do
      msg = {
        "type"   => "agent.status",
        "v"      => 2,
        "status" => {
          "agent_version"    => "1.0.0",
          "hostname"         => "test-host",
          "local_ip"         => "192.168.1.1",
          "environment"      => "test",
          "nickname"         => "test-agent",
          "uptime"           => 100.0,
          "timestamp"        => Time.utc.to_unix_f,
          "security_enabled" => false,
          "security_mode"    => "none",
          "active"           => false,
          "time_remaining"   => nil,
          "extendable"       => false,
        },
      }
      ProtocolHelper.assert_matches_schema(msg, "AgentStatusPayload")
    end

    it "agent.credentials has required fields" do
      msg = {
        "type"        => "agent.credentials",
        "v"           => 2,
        "credentials" => [
          {"name" => "Main DB", "uuid" => "abc-123", "type" => "postgres", "host" => "db.example.com"},
        ],
      }
      ProtocolHelper.assert_matches_schema(msg, "AgentCredentialsPayload")
    end

    it "agent.security.lockout has required fields" do
      msg = {
        "type"            => "agent.security.lockout",
        "v"               => 2,
        "lockout_mode"    => "temporary",
        "failed_attempts" => 5,
        "timestamp"       => Time.utc.to_unix_f,
      }
      ProtocolHelper.assert_matches_schema(msg, "AgentSecurityLockoutPayload")
    end

    it "heartbeat.ping has required fields" do
      msg = {
        "type"      => "heartbeat.ping",
        "v"         => 2,
        "timestamp" => Time.utc.to_unix_f,
      }
      ProtocolHelper.assert_matches_schema(msg, "HeartbeatPingPayload")
    end

    it "heartbeat.pong has required fields" do
      msg = {
        "type"      => "heartbeat.pong",
        "v"         => 2,
        "timestamp" => Time.utc.to_unix_f,
      }
      ProtocolHelper.assert_matches_schema(msg, "HeartbeatPongPayload")
    end

    it "heartbeat.pong with security info has required fields" do
      msg = {
        "type"             => "heartbeat.pong",
        "v"                => 2,
        "timestamp"        => Time.utc.to_unix_f,
        "security_enabled" => true,
        "security_mode"    => "totp",
        "active"           => true,
        "time_remaining"   => 1500,
        "extendable"       => true,
      }
      ProtocolHelper.assert_matches_schema(msg, "HeartbeatPongPayload")
    end

    it "session.provision has required fields" do
      msg = {
        "type" => "session.provision",
        "v"    => 2,
      }
      ProtocolHelper.assert_matches_schema(msg, "SessionProvisionPayload")
    end

    it "session.provision with all fields" do
      msg = {
        "type"            => "session.provision",
        "v"               => 2,
        "organization_id" => "550e8400-e29b-41d4-a716-446655440000",
        "environment"     => "production",
        "nickname"        => "my-agent",
      }
      ProtocolHelper.assert_matches_schema(msg, "SessionProvisionPayload")
    end
  end

  describe "server → agent messages (shape verification)" do
    it "session.created has required fields" do
      msg = {
        "type"         => "session.created",
        "v"            => 2,
        "machine_id"   => "550e8400-e29b-41d4-a716-446655440000",
        "connected_at" => "2026-03-21T10:00:00Z",
      }
      ProtocolHelper.assert_matches_schema(msg, "SessionCreatedPayload")
    end

    it "session.provisioning.created has required fields" do
      msg = {
        "type"                 => "session.provisioning.created",
        "v"                    => 2,
        "provisioning_version" => 1,
        "connected_at"         => "2026-03-21T10:00:00Z",
        "message"              => "Connected in provisioning mode.",
      }
      ProtocolHelper.assert_matches_schema(msg, "SessionProvisioningCreatedPayload")
    end

    it "command.request has required fields" do
      msg = {
        "type"       => "command.request",
        "v"          => 2,
        "request_id" => "req_abc123",
        "command"    => "ping",
      }
      ProtocolHelper.assert_matches_schema(msg, "CommandRequestPayload")
    end

    it "error has required fields" do
      msg = {
        "type"    => "error",
        "v"       => 2,
        "error"   => "invalid_access_key",
        "message" => "Invalid access key.",
      }
      ProtocolHelper.assert_matches_schema(msg, "ErrorPayload")
    end

    it "session.provisioned has required fields" do
      msg = {
        "type"            => "session.provisioned",
        "v"               => 2,
        "machine_key"     => "genkey-agent-abc123",
        "machine_id"      => "550e8400-e29b-41d4-a716-446655440000",
        "organization_id" => "660e8400-e29b-41d4-a716-446655440000",
        "environment"     => "production",
        "nickname"        => "my-agent",
      }
      ProtocolHelper.assert_matches_schema(msg, "SessionProvisionedPayload")
    end

    it "sync.updated has required fields" do
      msg = {
        "type"      => "sync.updated",
        "v"         => 2,
        "commit"    => "abc123def456",
        "timestamp" => "2026-03-21T10:00:00Z",
      }
      ProtocolHelper.assert_matches_schema(msg, "SyncUpdatedPayload")
    end
  end
end
