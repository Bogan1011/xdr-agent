#!/bin/sh
# Install and upgrade (deb: configure; rpm: $1 = 1 or 2).
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
# A maintenance window opened for this upgrade ends with it.
rm -f /var/lib/xdr-agent/maintenance.json
if [ -s /etc/xdr-agent/agent.yaml ]; then
  systemctl enable xdr-agent >/dev/null 2>&1 || true
  systemctl restart xdr-agent || true
else
  systemctl enable xdr-agent >/dev/null 2>&1 || true
  echo "xdr-agent installed but not enrolled. Run the install command from the console"
  echo "(Settings > Deploy agents) with --config-only added, for example:"
  echo "  curl -fsSL http://<console>:8080/install.sh | sudo bash -s -- --token <token> --ca-sha256 <fingerprint> --config-only"
fi
