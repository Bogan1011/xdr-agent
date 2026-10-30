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

# A packaged agent (.deb/.rpm) is removed with its package manager, which
# runs the same cleanup; the steps below then find little left to do.
if dpkg-query -W -f='${Status}' xdr-agent 2>/dev/null | grep -q 'ok installed'; then
  dpkg --purge xdr-agent || true
elif rpm -q xdr-agent >/dev/null 2>&1; then
  rpm -e xdr-agent || true
fi

if systemctl list-unit-files xdr-agent.service >/dev/null 2>&1; then
  systemctl disable --now xdr-agent 2>/dev/null || true
  nft delete table inet xdr_isolation 2>/dev/null || true
  nft delete table inet xdr_firewall 2>/dev/null || true
  nft delete table inet xdr_webrep 2>/dev/null || true
  nft delete table inet xdr_ips 2>/dev/null || true
fi

# USB storage devices that device control blocked would otherwise stay
# unusable until replugged.
if [[ -s /var/lib/xdr-agent/devctl.json ]]; then
  for dev in $(grep -o '"[0-9][0-9.-]*":{' /var/lib/xdr-agent/devctl.json | tr -d '":{'); do
    [[ -w "/sys/bus/usb/devices/$dev/authorized" ]] && echo 1 > "/sys/bus/usb/devices/$dev/authorized" || true
  done
fi
# Likewise USB disks made read-only, and filesystems remounted read-only on them.
if [[ -s /var/lib/xdr-agent/devctl-ro.json ]]; then
  for disk in $(grep -o '"[a-z0-9]*"' /var/lib/xdr-agent/devctl-ro.json | tr -d '"'); do
    [[ -b "/dev/$disk" ]] || continue
    blockdev --setrw "/dev/$disk" 2>/dev/null || true
    awk -v d="/dev/$disk" '$1 == d && $4 ~ /(^|,)ro(,|$)/ { print $2 }' /proc/self/mounts | while read -r mnt; do
      mount -o remount,rw "$(printf '%b' "$mnt")" 2>/dev/null || true
    done
  done
fi

rm -rf /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d
systemctl daemon-reload
rm -f /usr/local/bin/xdr-agent /etc/sudoers.d/xdr-jit-* /etc/sudoers.d/xdr-session-recording
rm -rf /etc/xdr-agent /var/lib/xdr-agent /run/xdr-agent
echo "xdr-agent removed. Delete the endpoint in the dashboard to drop its record."
