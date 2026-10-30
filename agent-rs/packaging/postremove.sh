#!/bin/sh
# Removal only. The agent's own drop-ins, sudoers files and state go with it,
# as with uninstall.sh; deb "remove" keeps the enrollment for a reinstall.
case "$1" in
  purge|0) rm -rf /etc/xdr-agent /var/lib/xdr-agent ;;
  remove) ;;
  *) exit 0 ;;
esac
rm -rf /etc/systemd/system/xdr-agent.service.d /run/xdr-agent
rm -f /etc/sudoers.d/xdr-jit-* /etc/sudoers.d/xdr-session-recording
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0
