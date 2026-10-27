# travelsec

Personal privacy/security auditing CLI (`python3 -m travelsec <wifi|room|home|dns-log>`) plus Claude Code skills in `.claude/skills/`.

## Layout

- `travelsec/common.py`: `Report`/`Finding` model (severity + scope `network|device`), `run()` subprocess wrapper, `net_info()`, firewall detection
- `travelsec/wifi.py`, `room.py`, `home.py`, `dnslog.py`: one module per mode, each exposing `run_<mode>() -> Report`
- `travelsec/bluetooth.py`: bluetoothctl scan/info parsers and tracker classification
- `travelsec/discovery.py`: mDNS (avahi), SSDP, WS-Discovery, ARP cache, UPnP descriptions
- `travelsec/dnsclient.py`: minimal stdlib DNS-over-UDP + DoH client
- `travelsec/oui.py`: MAC vendor lookup from system/IEEE files (never hardcode OUI prefixes)
- `scripts/`: dependency install, data fetch, temporary-firewall-opening wrapper (sudo)

## Rules

- Standard library only. External tools (nmap, bluetoothctl, avahi-browse, nmcli) are optional: degrade gracefully and `rep.note()` what was skipped.
- Scope boundary: `wifi` and `room` must stay passive toward third-party devices (listen, or test only the user's own traffic). Anything that probes devices belongs in `home`, behind the `authorize()` trusted-network check.
- Reports and the sightings/trust/baseline files live in `~/.local/share/travelsec` (`TRAVELSEC_HOME`), never in the repo.
- Parsers are tested against real tool output captured in `tests/`; when changing a parser, add the real output that broke it.
- Run tests: `python3 -m unittest discover -s tests`
