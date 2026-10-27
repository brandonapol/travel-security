# travelsec

Audit the devices and networks around you for surveillance and sloppy security: at home, in hotel rooms, and on café Wi-Fi.

| Mode | Where | What it does | Touches other devices? |
|---|---|---|---|
| `wifi` | any network you've joined | Checks what the network does to **your** traffic: captive portal, DNS hijacking & transparent interception, TLS interception, injected HTTP content/headers, evil-twin hotspots, client isolation, your own laptop's exposure. Gives a verdict. | No |
| `room` | hotel / rental / anywhere | Passive sweep: Wi-Fi beacons, BLE adverts (AirTag/Find My, Tile, SmartTag, camera-named devices), mDNS/SSDP/ONVIF announcements on the local network. Tracks trackers across locations. Prints a physical-inspection checklist. | No (listen only) |
| `home` | **networks you own** | Active inventory: host discovery, port/service scan, unauthenticated RTSP camera streams, anonymous MQTT, ADB/telnet, UPnP port mappings opened through your router, device-type guessing. | Yes, guarded by `--i-own-this-network` |
| `dns-log` | offline | Classifies a router / Pi-hole / AdGuard DNS log: TV content-recognition (ACR), telemetry, ad/analytics, IoT clouds, per device. | No |

The scope split is deliberate. Actively scanning other people's devices on a network you don't own is illegal in many places and breaks most venues' terms. On someone else's network this tool only listens, or tests your own connection.

## Setup

Python ≥ 3.11, standard library only. Linux with NetworkManager (`nmcli`), BlueZ (`bluetoothctl`), and avahi.

```bash
scripts/install-deps.sh      # installs nmap (+ avahi/bluez if missing) via sudo, then fetches data
scripts/fetch-data.sh        # just the data: IEEE MAC vendor list + tracker blocklist (no sudo)
```

Optional: `pip install -e .` puts `travelsec` on your PATH; otherwise use `python3 -m travelsec`.

## Usage

```bash
python3 -m travelsec wifi --baseline                  # once, at home: record trusted TLS issuers
python3 -m travelsec wifi --label "blue bottle"       # on any new network
python3 -m travelsec room --label "hotel lisbon 304"  # on arrival somewhere
python3 -m travelsec home --i-own-this-network        # first run at home (remembered after)
python3 -m travelsec dns-log ~/pihole.log
python3 -m travelsec --json <mode> ...                # full JSON instead of Markdown
```

Reports are saved as Markdown + JSON under `~/.local/share/travelsec/reports/` (override with `TRAVELSEC_HOME`). They contain MACs, SSIDs and location labels, so they never go in this repo.

### Firewalls and discovery

A default-deny host firewall (ufw on Omarchy, for example) drops replies to mDNS/SSDP discovery, so `room`'s LAN section and `home`'s device list come back thin. That's the right default while traveling. When you want a full scan:

```bash
sudo scripts/with-discovery.sh home --i-own-this-network
sudo scripts/with-discovery.sh room --label "airbnb"
```

This inserts one ufw rule (inbound UDP from the local subnet, current interface only) for the duration of the run, removes it on exit, and runs as root so nmap can use ARP discovery and SYN scans.

## Claude Code skills

In `.claude/skills/`. Each one runs the matching mode and turns the JSON into a prioritized, plain-language answer:

- `/wifi-check`: "is this network spying on me?"
- `/room-sweep`: cameras, trackers, and a guided physical check
- `/home-audit`: device inventory and fix-first list, plus DNS-log analysis of TV/IoT telemetry

## Limits

- RF sweeps can't see cameras that record to an SD card with no radio. Do the physical check.
- A laptop on Wi-Fi can't see other devices' traffic. For "what is my TV sending", use DNS logs from your router, Pi-hole or AdGuard Home.
- Vendor and SSID heuristics are hints. Signal strength is what tells you whether something is in *your* room.
- Linux only for now (macOS would need `airport`/CoreBluetooth equivalents).

## Tests

```bash
python3 -m unittest discover -s tests
```
