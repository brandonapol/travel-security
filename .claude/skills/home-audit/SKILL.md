---
name: home-audit
description: Inventory and security-audit every device on the user's own home network — cameras, smart TVs, IoT gadgets, routers — finding open telnet/ADB/RTSP, unauthenticated camera streams and MQTT brokers, UPnP holes punched through the router, and (from a router/Pi-hole DNS log) which devices phone home to trackers and TV content-recognition services. Use when the user asks to audit their home network, find insecure IoT devices, or check what their smart TV is sending.
---

# Home network audit

Runs `travelsec home`, which is **active** (ping sweep, port scan, service probes). Only run it on a network the user owns or is explicitly authorized to test.

## Authorization

The tool remembers trusted networks by router MAC. On an untrusted network it refuses (exit code 2) and the report says "Not authorized to scan this network".

- If the user has clearly said *this* is their home network, re-run with `--i-own-this-network`.
- If there's any doubt (they might be at a hotel, a friend's place, or work), **ask** before adding the flag. Never add it on a public or shared network.

## Steps

1. Basic run (works without sudo; uses nmap if installed):
   ```bash
   python3 -m travelsec --json home [--i-own-this-network]
   ```
2. If the notes say nmap is missing, or that the firewall blocks discovery, suggest the user run, in their own terminal (both need sudo):
   - `scripts/install-deps.sh` (installs nmap once)
   - `sudo scripts/with-discovery.sh home --i-own-this-network` (root gives ARP discovery, SYN scans, and the temporary firewall opening). Afterwards, read the newest JSON in `~/.local/share/travelsec/reports/`.
3. Optionally, `--full` scans nmap's top 1000 ports instead of the curated IoT list.
4. For "what is my TV sending": the laptop can't see other devices' traffic. Ask the user to export DNS logs from their router, Pi-hole, or AdGuard Home and run `python3 -m travelsec --json dns-log <file>`. If they have no DNS logging yet, suggest AdGuard Home or Pi-hole (many routers, e.g. GL.iNet and OpenWrt, can run AdGuard Home themselves).

## How to interpret

Produce:

1. **A device table**: every device in `data.inventory` with its type, best name, vendor, and open ports. Point out unknown devices, and suggest matching them through the router's client list.
2. **Fix-first list**, most urgent first:
   - Camera stream viewable without a password, anonymous MQTT, ADB (5555), telnet, Xiongmai/Dahua DVR ports → **high**: these give real access or control. Give the specific fix: set a password, update firmware, disable developer mode, or replace devices that can't be fixed.
   - UPnP port mappings → say which internal device opened which port to the internet, and whether that's expected (game consoles, Plex) or alarming (a camera or DVR).
   - Plain-HTTP admin pages, SMB, printer ports, and Roku ECP → low; mention briefly.
3. **Old firmware**: when nmap supplies `product`/version strings, flag old software you recognize (e.g. Dropbear or BusyBox from many years ago, lighttpd 1.4.3x, GoAhead) as likely unpatched. Say this is a judgment from version age, not a CVE lookup.
4. **Isolation advice**: if there are cameras, TVs, or no-name IoT devices, recommend moving them to a separate guest or IoT network or VLAN, and turning off UPnP on the router.

For dns-log results: `tv-acr` means the TV reports what's on screen. Name the setting to disable for that brand (Samsung: Viewing Information Services / Interest-Based Ads; LG: Live Plus; Vizio: Viewing Data; Roku: Smart TV experience → Use info from TV inputs; Sony/Google TV: Samba Interactive TV). Also suggest blocking the listed domains in the router's DNS.
