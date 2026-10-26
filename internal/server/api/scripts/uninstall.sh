#!/usr/bin/env bash
# Removes the XDR agent, its config and its identity from this host.
#
#   curl -fsSL http://<server>/uninstall.sh | sudo bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

if systemctl list-unit-files xdr-agent.service >/dev/null 2>&1; then
  systemctl disable --now xdr-agent 2>/dev/null || true
  nft delete table inet xdr_isolation 2>/dev/null || true
fi
rm -f /etc/systemd/system/xdr-agent.service
systemctl daemon-reload
rm -f /usr/local/bin/xdr-agent
rm -rf /etc/xdr-agent /var/lib/xdr-agent
echo "xdr-agent removed. Delete the endpoint in the dashboard to drop its record."
