# gentility-gateway-install MOVE_ID BUNDLE_URL SHA256
# gentility-gateway-install --recover
#
# Run by the gentility agent through sudo, and with --recover by
# gentility-gateway-recover.service at boot; see src/gateway_install/installer.cr.
require "./gateway_install/installer"

status, answer = GatewayInstaller::Installer.new(GatewayInstaller::HostSystem.new).run(ARGV)
begin
  puts answer unless answer.empty?
rescue IO::Error
  # The caller has gone; the answer is in the move's record.
end
exit status
