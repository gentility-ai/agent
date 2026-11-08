# gentility-gateway-install MOVE_ID BUNDLE_URL SHA256
#
# Run by the gentility agent through sudo; see src/gateway_install/installer.cr.
require "./gateway_install/installer"

status, answer = GatewayInstaller::Installer.new(GatewayInstaller::HostSystem.new).run(ARGV)
puts answer
exit status
