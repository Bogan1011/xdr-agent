#!/usr/bin/env bash
# Removes the XDR agent, its config and its identity from this host.
#
#   curl -fsSL http://<server>/uninstall.sh | sudo bash
#
# When tamper protection is on, pass the maintenance token shown on the
# endpoint's page in the console:
#
#   curl -fsSL http://<server>/uninstall.sh | sudo bash -s -- --token <token>
set -euo pipefail

TOKEN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

if [[ -e /etc/systemd/system/xdr-agent.service.d/10-tamper-protection.conf ]]; then
  if [[ -z "$TOKEN" ]]; then
    echo "tamper protection is on: uninstall from the console, or rerun with --token <maintenance token from the endpoint's page>" >&2
    exit 1
  fi
  /usr/local/bin/xdr-agent maintenance --token "$TOKEN" || exit 1
fi

if systemctl list-unit-files xdr-agent.service >/dev/null 2>&1; then
  systemctl disable --now xdr-agent 2>/dev/null || true
  nft delete table inet xdr_isolation 2>/dev/null || true
fi
rm -rf /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d
systemctl daemon-reload
rm -f /usr/local/bin/xdr-agent /etc/sudoers.d/xdr-jit-* /etc/sudoers.d/xdr-session-recording
rm -rf /etc/xdr-agent /var/lib/xdr-agent /run/xdr-agent
echo "xdr-agent removed. Delete the endpoint in the dashboard to drop its record."
