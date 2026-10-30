#!/bin/sh
# Removal only (deb: remove/purge; rpm: $1 = 0). Upgrades keep the agent running
# until postinstall restarts it.
case "$1" in
  remove|purge|0) ;;
  *) exit 0 ;;
esac
if [ -e /etc/systemd/system/xdr-agent.service.d/10-tamper-protection.conf ] &&
  [ ! -e /var/lib/xdr-agent/maintenance.json ]; then
  echo "tamper protection is on: run 'sudo xdr-agent maintenance --token <token from the endpoint's page>' first, or uninstall from the console" >&2
  exit 1
fi
systemctl disable --now xdr-agent >/dev/null 2>&1 || true
for t in xdr_isolation xdr_firewall xdr_webrep xdr_ips; do
  nft delete table inet "$t" 2>/dev/null || true
done
# USB storage that device control blocked or made read-only would stay so.
if [ -s /var/lib/xdr-agent/devctl.json ]; then
  for dev in $(grep -o '"[0-9][0-9.-]*":{' /var/lib/xdr-agent/devctl.json | tr -d '":{'); do
    [ -w "/sys/bus/usb/devices/$dev/authorized" ] && echo 1 > "/sys/bus/usb/devices/$dev/authorized" || true
  done
fi
if [ -s /var/lib/xdr-agent/devctl-ro.json ]; then
  for disk in $(grep -o '"[a-z0-9]*"' /var/lib/xdr-agent/devctl-ro.json | tr -d '"'); do
    [ -b "/dev/$disk" ] || continue
    blockdev --setrw "/dev/$disk" 2>/dev/null || true
    awk -v d="/dev/$disk" '$1 == d && $4 ~ /(^|,)ro(,|$)/ { print $2 }' /proc/self/mounts | while read -r mnt; do
      mount -o remount,rw "$(printf '%b' "$mnt")" 2>/dev/null || true
    done
  done
fi
exit 0
