#!/usr/bin/env bash
# Install the system tools travelsec uses. Run from your normal account; it calls sudo itself.
#   nmap        - host discovery + service/version detection for `travelsec home`
#   avahi       - mDNS discovery (usually already present)
#   bluez-utils - bluetoothctl for BLE sweeps (usually already present)
set -euo pipefail

if command -v pacman >/dev/null; then
  sudo pacman -S --needed nmap avahi bluez-utils
  sudo systemctl enable --now avahi-daemon bluetooth
elif command -v apt-get >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y nmap avahi-utils bluez
elif command -v dnf >/dev/null; then
  sudo dnf install -y nmap avahi-tools bluez
elif command -v brew >/dev/null; then
  # macOS: nmap works; Wi-Fi/BLE scanning use different OS tools and aren't supported yet.
  brew install nmap
else
  echo "Unknown package manager; install nmap, avahi(-utils) and bluez yourself." >&2
  exit 1
fi

"$(dirname "$0")/fetch-data.sh"
echo "Done. Try: python3 -m travelsec wifi --baseline   (on a network you trust)"
