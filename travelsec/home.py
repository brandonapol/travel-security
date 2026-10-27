"""`travelsec home`: inventory and audit a network you own.

This mode is active: it pings, port-scans and talks to devices. It refuses to
run unless the current network (identified by router MAC) is on your trusted
list, which you add to with --i-own-this-network.
"""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import ipaddress
import re
import socket
import struct
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from . import oui
from .common import DATA_DIR, Report, discovery_blocked_note, firewall, have, is_root, load_json, net_info, run, save_json
from .discovery import _strip_ns, arp_neighbors, mdns_browse, ssdp_search, upnp_describe

TRUSTED = DATA_DIR / "trusted-networks.json"
MAX_HOSTS = 1024

# port -> (service, severity if open, why it matters)
PORTS: dict[int, tuple[str, str, str]] = {
    21: ("ftp", "medium", "FTP sends passwords in cleartext."),
    22: ("ssh", "info", "Remote shell. Fine on computers; on IoT gear often has default passwords."),
    23: ("telnet", "high", "Telnet: cleartext remote shell. The #1 way IoT botnets (Mirai) take over devices."),
    53: ("dns", "info", ""),
    80: ("http", "low", "Web admin over plain HTTP: passwords cross the network unencrypted."),
    139: ("netbios", "low", "Windows/SMB file sharing."),
    443: ("https", "info", ""),
    445: ("smb", "low", "SMB file sharing; make sure guest access is off."),
    554: ("rtsp", "medium", "RTSP video stream: this is a camera or NVR."),
    631: ("ipp", "info", "Printer."),
    1883: ("mqtt", "medium", "MQTT smart-home message broker."),
    1900: ("upnp", "low", "UPnP."),
    2323: ("telnet-alt", "high", "Alternate telnet port, typical of cheap IoT firmware."),
    3000: ("lg-webos", "info", "LG webOS TV control."),
    3001: ("lg-webos-tls", "info", "LG webOS TV control."),
    3389: ("rdp", "medium", "Remote Desktop."),
    5000: ("upnp/http", "info", ""),
    5555: ("adb", "high", "Android Debug Bridge open: anyone on your Wi-Fi can install apps or take full control "
                          "(common on Android TVs / Fire TV with developer mode)."),
    5900: ("vnc", "medium", "VNC remote screen, often weakly protected."),
    6668: ("tuya", "low", "Tuya smart-device local control."),
    7547: ("tr-069", "medium", "ISP remote-management interface (CWMP); historically exploited."),
    8000: ("http-alt", "low", "Web admin over plain HTTP (common on DVRs/cameras)."),
    8001: ("samsung-tv", "info", "Samsung TV remote control API."),
    8002: ("samsung-tv-tls", "info", "Samsung TV remote control API."),
    8008: ("chromecast", "info", "Chromecast / Google Cast."),
    8009: ("chromecast-tls", "info", "Google Cast."),
    8060: ("roku-ecp", "low", "Roku control API: no authentication, anyone on the LAN can control it and read what's installed."),
    8080: ("http-alt", "low", "Web admin over plain HTTP."),
    8081: ("http-alt", "low", "Web admin over plain HTTP."),
    8443: ("https-alt", "info", ""),
    8554: ("rtsp-alt", "medium", "RTSP video stream: this is a camera or NVR."),
    8888: ("http-alt", "low", "Web admin over plain HTTP."),
    9100: ("jetdirect", "low", "Raw printing port; anyone can send print jobs."),
    9999: ("tplink-kasa", "low", "TP-Link Kasa smart plug local API (historically unauthenticated)."),
    34567: ("xiongmai-dvr", "high", "Xiongmai DVR/camera control port: notoriously insecure firmware."),
    37777: ("dahua-dvr", "high", "Dahua DVR/camera control port; many known authentication bypasses."),
    49152: ("upnp", "info", ""),
    55443: ("tuya-tls", "info", ""),
}
HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 5000, 49152}


# --- authorization -----------------------------------------------------------------

def authorize(net, confirm: bool) -> str | None:
    """Return an error message if this network isn't one the user said they own."""
    trusted = load_json(TRUSTED, [])
    key = (net.gateway_mac or "").lower()
    if not key:
        return "Couldn't identify the router (no gateway MAC). Ping the gateway once and retry."
    if any(t["gateway_mac"] == key for t in trusted):
        return None
    if not confirm:
        return (f"This network (router {key}, SSID '{net.ssid or 'wired'}') is not on your trusted list. "
                "Home mode actively scans devices; only run it on a network you own or are authorized to test. "
                "If this is yours, re-run with --i-own-this-network.")
    trusted.append({"gateway_mac": key, "ssid": net.ssid, "added": dt.date.today().isoformat()})
    save_json(TRUSTED, trusted)
    return None


# --- discovery ---------------------------------------------------------------------

def _ping(ip: str) -> bool:
    return subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True).returncode == 0


def discover_hosts(rep: Report, net) -> set[str]:
    network = ipaddress.ip_network(net.cidr)
    hosts: set[str] = set()
    if have("nmap"):
        out = run(["nmap", "-sn", "-n", "-oX", "-", net.cidr], timeout=300)
        try:
            for h in ET.fromstring(out).iter("host"):
                for a in h.iter("address"):
                    if a.get("addrtype") == "ipv4":
                        hosts.add(a.get("addr"))
        except ET.ParseError:
            rep.note("nmap host discovery failed; falling back to ping sweep.")
    if not hosts:
        if network.num_addresses > 256:
            rep.note("Ping sweep limited to the /24 around you; install nmap for larger networks.")
            network = ipaddress.ip_interface(f"{net.address}/24").network
        with cf.ThreadPoolExecutor(64) as ex:
            ips = [str(i) for i in network.hosts()]
            hosts |= {ip for ip, up in zip(ips, ex.map(_ping, ips)) if up}
    hosts |= {n["ip"] for n in arp_neighbors(net.iface)}
    return {h for h in hosts if ipaddress.ip_address(h) in ipaddress.ip_network(net.cidr)}


def _connect(ip: str, port: int) -> bool:
    try:
        socket.create_connection((ip, port), timeout=1.0).close()
        return True
    except OSError:
        return False


def scan_ports(rep: Report, hosts: list[str], full: bool) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {h: [] for h in hosts}
    if have("nmap"):
        ports = ["--top-ports", "1000"] if full else ["-p", ",".join(map(str, sorted(PORTS)))]
        out = run(["nmap", "-sV", "--version-light", "-T4", "-Pn", "-n", *ports, "-oX", "-", *hosts], timeout=1800)
        try:
            for h in ET.fromstring(out).iter("host"):
                ip = next(a.get("addr") for a in h.iter("address") if a.get("addrtype") == "ipv4")
                for p in h.iter("port"):
                    if p.find("state").get("state") != "open":
                        continue
                    svc = p.find("service")
                    found.setdefault(ip, []).append({
                        "port": int(p.get("portid")), "proto": p.get("protocol"),
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": " ".join(filter(None, [svc.get("product"), svc.get("version"), svc.get("extrainfo")]))
                                   if svc is not None else "",
                    })
            return found
        except (ET.ParseError, StopIteration):
            rep.note("nmap port scan output unreadable; falling back to built-in scanner.")
    pairs = [(h, p) for h in hosts for p in PORTS]
    with cf.ThreadPoolExecutor(128) as ex:
        for (h, p), ok in zip(pairs, ex.map(lambda hp: _connect(*hp), pairs)):
            if ok:
                found[h].append({"port": p, "proto": "tcp", "service": PORTS[p][0], "product": ""})
    return found


# --- deeper checks on specific services --------------------------------------------

def rtsp_open(ip: str, port: int) -> int | None:
    """Returns RTSP status for DESCRIBE on the root path (200 = streams without a password)."""
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.sendall(f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".encode())
            m = re.match(rb"RTSP/1\.\d (\d{3})", s.recv(1024))
            return int(m.group(1)) if m else None
    except OSError:
        return None


def mqtt_anonymous(ip: str, port: int = 1883) -> bool | None:
    cid = b"travelsec"
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = struct.pack(">H", len(cid)) + cid
    pkt = b"\x10" + bytes([len(var) + len(payload)]) + var + payload
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.sendall(pkt)
            r = s.recv(4)
            s.sendall(b"\xe0\x00")
            return len(r) == 4 and r[0] == 0x20 and r[3] == 0
    except OSError:
        return None


def http_info(ip: str, port: int) -> dict:
    try:
        with urllib.request.urlopen(f"http://{ip}:{port}/", timeout=4) as r:
            body, server, status = r.read(100_000), r.headers.get("Server", ""), r.status
    except urllib.error.HTTPError as e:
        body, server, status = e.read(100_000), e.headers.get("Server", ""), e.code
    except Exception:
        return {}
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {"status": status, "server": server, "title": m.group(1).decode(errors="replace").strip()[:120] if m else ""}


def banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.settimeout(3)
            return s.recv(256).decode(errors="replace").strip()
    except OSError:
        return ""


def upnp_port_mappings(desc: dict) -> list[dict]:
    """Ask the router (UPnP IGD) which ports devices have opened to the internet."""
    out = []
    for svc in desc["services"]:
        if not re.search(r"WAN(IP|PPP)Connection", svc["type"]):
            continue
        url = urllib.parse.urljoin(desc["location"], svc["control"])
        for i in range(128):
            body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                    f'<u:GetGenericPortMappingEntry xmlns:u="{svc["type"]}"><NewPortMappingIndex>{i}</NewPortMappingIndex>'
                    f'</u:GetGenericPortMappingEntry></s:Body></s:Envelope>').encode()
            req = urllib.request.Request(url, data=body, headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{svc["type"]}#GetGenericPortMappingEntry"'})
            try:
                with urllib.request.urlopen(req, timeout=4) as r:
                    root = _strip_ns(ET.fromstring(r.read()))
            except Exception:
                break
            g = lambda t: (root.findtext(f".//{t}") or "").strip()
            out.append({"external_port": g("NewExternalPort"), "protocol": g("NewProtocol"),
                        "internal_client": g("NewInternalClient"), "internal_port": g("NewInternalPort"),
                        "description": g("NewPortMappingDescription"), "enabled": g("NewEnabled")})
    return out


# --- device typing -----------------------------------------------------------------

def guess_type(dev: dict) -> str:
    ports = {p["port"] for p in dev["ports"]}
    cats = {s["category"] for s in dev["mdns"] if s["category"]}
    upnp = " ".join(u.get("deviceType", "") + " " + u.get("manufacturer", "") for u in dev["upnp"]).lower()
    if dev.get("is_gateway"):
        return "router"
    if ports & {554, 8554, 34567, 37777} or "camera" in cats or "camera" in dev["category"] or "camera" in upnp:
        return "camera/NVR"
    if ports & {8060, 8008, 8009, 8001, 8002, 3000, 3001} or "tv/streaming" in cats or "mediarenderer" in upnp:
        return "TV/streaming"
    if ports & {9100, 631} or "printer" in cats:
        return "printer"
    if "speaker" in cats:
        return "speaker"
    if "smart-home" in cats or dev["category"] == "iot-module" or ports & {6668, 9999, 55443}:
        return "smart-home/IoT"
    if "computer" in cats:
        return "computer"
    return dev["category"] or "unknown"


def run_home(confirm: bool = False, full: bool = False, force: bool = False) -> Report:
    rep = Report("home")
    net = net_info()
    rep.data["network"] = {k: v for k, v in vars(net).items()}
    if not net.cidr:
        rep.add("high", "No network connection")
        return rep
    if err := authorize(net, confirm):
        rep.add("info", "Not authorized to scan this network", err)
        rep.data["refused"] = True
        return rep
    if ipaddress.ip_network(net.cidr).num_addresses > MAX_HOSTS and not force:
        rep.add("info", f"Network {net.cidr} is large", "Re-run with --force to scan it anyway.")
        return rep
    if not have("nmap"):
        rep.note("nmap not installed: using built-in ping sweep + connect scan (no version detection). "
                 "Run scripts/install-deps.sh for better results.")

    hosts = sorted(discover_hosts(rep, net) - {net.address}, key=lambda h: ipaddress.ip_address(h))
    macs = {n["ip"]: n["mac"] for n in arp_neighbors(net.iface)}
    mdns = mdns_browse(timeout=12)
    ssdp = ssdp_search(seconds=5)
    descs: dict[str, list[dict]] = {}
    for loc in sorted({s["location"] for s in ssdp if s["location"]}):
        if d := upnp_describe(loc):
            descs.setdefault(urllib.parse.urlparse(loc).hostname, []).append(d)
    if not mdns and not ssdp and (note := discovery_blocked_note(firewall())):
        rep.note(note)
    if have("nmap") and not is_root():
        rep.note("nmap running unprivileged (TCP connect scan, no ARP discovery). sudo scripts/with-discovery.sh gives better coverage.")
    hosts = sorted(set(hosts) | set(descs) | {s["ip"] for s in mdns if s["ip"] != net.address},
                   key=lambda h: ipaddress.ip_address(h))
    ports = scan_ports(rep, hosts, full)

    inventory = []
    for ip in hosts:
        mac = macs.get(ip, "")
        info = oui.describe(mac) if mac else {"vendor": "unknown", "category": None}
        dev = {
            "ip": ip, "mac": mac, "vendor": info["vendor"], "category": info["category"] or "",
            "is_gateway": ip == net.gateway,
            "names": sorted({s["name"] for s in mdns if s["ip"] == ip} | {d["friendlyName"] for d in descs.get(ip, []) if d["friendlyName"]}),
            "mdns": [s for s in mdns if s["ip"] == ip],
            "upnp": [{k: d[k] for k in ("deviceType", "friendlyName", "manufacturer", "modelName", "modelNumber")} for d in descs.get(ip, [])],
            "ports": ports.get(ip, []),
            "details": {},
        }
        try:
            dev["rdns"] = socket.gethostbyaddr(ip)[0]
        except OSError:
            dev["rdns"] = ""
        dev["type"] = guess_type(dev)
        name = (dev["names"] or [dev["rdns"] or dev["vendor"]])[0]
        who = f"{name} ({ip})"

        for p in dev["ports"]:
            port = p["port"]
            svc, sev, why = PORTS.get(port, (p["service"], "info", ""))
            if port in (554, 8554):
                code = rtsp_open(ip, port)
                dev["details"][f"rtsp_{port}"] = code
                if code == 200:
                    rep.add("high", f"Camera stream viewable without a password: {who}",
                            "Anyone on your network can watch this feed. Set a strong password / update firmware.", ip=ip, port=port)
                    continue
                if code == 401:
                    sev, why = "low", "RTSP camera stream (password required)."
            elif port == 1883:
                if mqtt_anonymous(ip):
                    sev, why = "high", "MQTT broker accepts anonymous clients: anyone on the LAN can read and control smart-home devices."
            elif port in (23, 2323):
                dev["details"][f"banner_{port}"] = banner(ip, port)
            if port in HTTP_PORTS:
                dev["details"][f"http_{port}"] = http_info(ip, port)
            if sev != "info":
                seen = dev["details"].get(f"http_{port}") or dev["details"].get(f"banner_{port}") or ""
                rep.add(sev, f"{who}: {svc} open (port {port})", why, ip=ip, port=port, product=p.get("product", ""),
                        vendor=dev["vendor"], type=dev["type"], **({"seen": seen} if seen else {}))
        inventory.append(dev)

    # Router: UPnP and holes punched to the internet
    for d in descs.get(net.gateway, []) + [d for ds in descs.values() for d in ds if "InternetGatewayDevice" in d["deviceType"]]:
        if any(re.search(r"WAN(IP|PPP)Connection", s["type"]) for s in d["services"]):
            rep.add("low", "UPnP port forwarding is enabled on your router",
                    "Any device on your network (including a compromised camera) can open ports to the internet "
                    "without asking. Disable UPnP in the router unless a game console needs it.")
            maps = upnp_port_mappings(d)
            rep.data["upnp_port_mappings"] = maps
            for m in maps:
                rep.add("medium", f"Port {m['external_port']}/{m['protocol']} is open to the internet → {m['internal_client']}",
                        f"Opened via UPnP ({m['description'] or 'no description'}). Make sure you know why.", **m)
            break

    unknown = [d for d in inventory if d["type"] == "unknown"]
    if unknown:
        rep.add("info", f"{len(unknown)} device(s) couldn't be identified",
                "Check the router's client list for names, or unplug things one at a time to match them up.",
                devices=[f"{d['ip']} {d['mac']} {d['vendor']}" for d in unknown])
    rep.data["inventory"] = inventory
    rep.notes.append("Traffic from TVs/IoT isn't visible from a laptop on Wi-Fi. To see who they phone home to, export "
                     "your router / Pi-hole / AdGuard DNS log and run `travelsec dns-log <file>`.")
    return rep
