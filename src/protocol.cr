# Single project-wide source of truth for the agent↔server capability
# version ("capver"). Bumped each time the agent gains a server-visible
# capability so the server can branch cleanly on what to expect.
#
# Capver is declared once at handshake via the `version` query param on
# the websocket connect URL. It is NOT the same as the per-message `v`
# field that older protocol versions emitted on every frame — capver 4
# dropped that field entirely. See protocol/capvers.md in the server
# repo for the canonical history.
module Protocol
  CAPVER = 4

  # The provisioning protocol's own version, sent as `pv` on every
  # `session.provision`. It is NOT capver and NOT the v2 message
  # namespace: the server refuses any value but the one it advertises as
  # `provisioning_version` on `session.provisioning.created`.
  PROVISIONING_VERSION = 1
end
