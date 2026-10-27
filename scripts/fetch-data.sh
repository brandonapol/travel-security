#!/usr/bin/env bash
# Download reference data into ~/.local/share/travelsec (no sudo needed):
#   oui.csv             - IEEE MAC vendor registry (fresher than the OS copy)
#   blocklist-hosts.txt - StevenBlack unified ad/tracker hosts list, for `travelsec dns-log`
set -euo pipefail
DIR="${TRAVELSEC_HOME:-$HOME/.local/share/travelsec}"
mkdir -p "$DIR"
curl -fsSL --retry 2 -o "$DIR/oui.csv.tmp" https://standards-oui.ieee.org/oui/oui.csv && mv "$DIR/oui.csv.tmp" "$DIR/oui.csv"
curl -fsSL --retry 2 -o "$DIR/blocklist-hosts.txt.tmp" https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
  && mv "$DIR/blocklist-hosts.txt.tmp" "$DIR/blocklist-hosts.txt"
echo "Reference data updated in $DIR"
