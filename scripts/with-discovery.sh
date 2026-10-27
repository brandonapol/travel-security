#!/usr/bin/env bash
# Run a travelsec mode as root with a temporary firewall opening for LAN discovery replies.
#
#   sudo scripts/with-discovery.sh home --i-own-this-network
#   sudo scripts/with-discovery.sh room --label "hotel lisbon"
#
# Why: a default-deny host firewall (ufw on Omarchy) drops mDNS/SSDP/WS-Discovery replies, so
# devices on the network stay invisible. This inserts ONE rule, inbound UDP from the local subnet
# on the current interface only, and removes it on exit (including Ctrl-C). Root also lets nmap
# use ARP discovery and SYN scans. Reports are written to your normal user's data dir.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0 $*" >&2; exit 1; }
: "${SUDO_USER:?Run via sudo from your normal account}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
export TRAVELSEC_HOME="${TRAVELSEC_HOME:-$USER_HOME/.local/share/travelsec}"

read -r IFACE NET < <(python3 - <<'PY'
import ipaddress, json, subprocess
r = json.loads(subprocess.run(["ip", "-j", "route", "show", "default"], capture_output=True, text=True).stdout)[0]
for a in json.loads(subprocess.run(["ip", "-j", "addr", "show", "dev", r["dev"]], capture_output=True, text=True).stdout):
    for ai in a["addr_info"]:
        if ai["family"] == "inet":
            print(r["dev"], ipaddress.ip_interface(f"{ai['local']}/{ai['prefixlen']}").network)
            raise SystemExit
PY
)

RULE=()
if systemctl is-active --quiet ufw; then
  RULE=(allow in on "$IFACE" proto udp from "$NET")
  cleanup() { ufw delete "${RULE[@]}" >/dev/null && echo "[travelsec] firewall rule removed" >&2; }
  trap cleanup EXIT
  ufw insert 1 "${RULE[@]}" comment travelsec-temp >/dev/null
  echo "[travelsec] temporarily allowing inbound UDP from $NET on $IFACE" >&2
fi

cd "$REPO"
status=0
python3 -m travelsec "$@" || status=$?
chown -R "$SUDO_USER": "$TRAVELSEC_HOME"
exit $status
