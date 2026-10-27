"""Local network discovery: mDNS, SSDP/UPnP, WS-Discovery (ONVIF cameras), ARP cache.

`passive_*` functions only listen to announcements devices already broadcast.
`ssdp_search` sends a standard UPnP discovery request (what any phone or TV
app does). Use it on networks you own.
"""

from __future__ import annotations

import re
import select
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ET

from .common import run, run_json

SSDP_ADDR, SSDP_PORT = "239.255.255.250", 1900
WSD_PORT = 3702

# mDNS service types worth calling out
MDNS_HINTS = {
    "_rtsp._tcp": ("camera", "RTSP video stream"),
    "_axis-video._tcp": ("camera", "Axis network camera"),
    "_onvif._tcp": ("camera", "ONVIF camera"),
    "_hap._tcp": ("smart-home", "HomeKit accessory (could be a camera, lock, sensor)"),
    "_homekit._tcp": ("smart-home", "HomeKit accessory"),
    "_googlecast._tcp": ("tv/streaming", "Chromecast / Google TV"),
    "_airplay._tcp": ("tv/streaming", "AirPlay receiver"),
    "_raop._tcp": ("tv/streaming", "AirPlay audio"),
    "_amzn-wplay._tcp": ("tv/streaming", "Amazon Fire TV"),
    "_spotify-connect._tcp": ("speaker", "Spotify Connect speaker"),
    "_sonos._tcp": ("speaker", "Sonos speaker"),
    "_matter._tcp": ("smart-home", "Matter device"),
    "_meshcop._udp": ("smart-home", "Thread border router"),
    "_printer._tcp": ("printer", "Printer"),
    "_ipp._tcp": ("printer", "Printer (IPP)"),
    "_smb._tcp": ("file-share", "SMB file share"),
    "_ssh._tcp": ("computer", "SSH server"),
    "_workstation._tcp": ("computer", "Computer"),
}


def _unescape_avahi(s: str) -> str:
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s)


def mdns_browse(timeout: float = 15) -> list[dict]:
    """Resolve every mDNS service on the LAN via avahi (standard OS discovery)."""
    out = run(["avahi-browse", "-a", "-t", "-r", "-p"], timeout=timeout)
    services, seen = [], set()
    for line in out.splitlines():
        f = line.split(";")
        if len(f) < 9 or f[0] != "=" or f[2] != "IPv4":
            continue
        key = (f[3], f[4], f[7])
        if key in seen:
            continue
        seen.add(key)
        stype = f[4]
        cat, desc = MDNS_HINTS.get(stype, (None, None))
        services.append({
            "name": _unescape_avahi(f[3]), "type": stype, "host": f[6], "ip": f[7],
            "port": int(f[8]) if f[8].isdigit() else None,
            "txt": _unescape_avahi(f[9]) if len(f) > 9 else "",
            "category": cat, "description": desc,
        })
    return services


def arp_neighbors(iface: str | None = None) -> list[dict]:
    cmd = ["ip", "-j", "neigh", "show"] + (["dev", iface] if iface else [])
    out = []
    for n in run_json(cmd) or []:
        if n.get("lladdr") and "." in n.get("dst", "") and "FAILED" not in n.get("state", []):
            out.append({"ip": n["dst"], "mac": n["lladdr"].lower()})
    return out


def _parse_http_headers(data: bytes) -> dict:
    lines = data.decode(errors="replace").split("\r\n")
    h = {"_start": lines[0]}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            h[k.strip().upper()] = v.strip()
    return h


def _mcast_listener(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("", port))
    mreq = struct.pack("4s4s", socket.inet_aton(SSDP_ADDR), socket.inet_aton("0.0.0.0"))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return s


def passive_listen(seconds: float = 20) -> dict:
    """Listen (send nothing) for SSDP NOTIFY and WS-Discovery Hello broadcasts."""
    socks, result = {}, {"ssdp": [], "wsd": [], "errors": []}
    for name, port in (("ssdp", SSDP_PORT), ("wsd", WSD_PORT)):
        try:
            socks[name] = _mcast_listener(port)
        except OSError as e:
            result["errors"].append(f"{name}: {e}")
    seen = set()
    deadline = time.monotonic() + seconds
    while socks and (left := deadline - time.monotonic()) > 0:
        ready, _, _ = select.select(list(socks.values()), [], [], left)
        for s in ready:
            data, (ip, _) = s.recvfrom(65535)
            kind = next(k for k, v in socks.items() if v is s)
            if kind == "ssdp":
                h = _parse_http_headers(data)
                if not h["_start"].startswith("NOTIFY"):
                    continue  # M-SEARCH requests from other hosts
                key = (ip, h.get("USN", ""))
                if key not in seen:
                    seen.add(key)
                    result["ssdp"].append({"ip": ip, "nt": h.get("NT", ""), "server": h.get("SERVER", ""),
                                           "location": h.get("LOCATION", ""), "usn": h.get("USN", "")})
            else:
                text = data.decode(errors="replace")
                if (ip, text[:200]) not in seen:
                    seen.add((ip, text[:200]))
                    result["wsd"].append({"ip": ip, "onvif": "onvif" in text.lower(), "snippet": text[:400]})
    for s in socks.values():
        s.close()
    return result


def ssdp_search(seconds: float = 5, st: str = "ssdp:all") -> list[dict]:
    """Active UPnP discovery (M-SEARCH). Every device replies with its description URL."""
    msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\n"
           f"MX: 2\r\nST: {st}\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.5)
    out, seen = [], set()
    try:
        s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                data, (ip, _) = s.recvfrom(65535)
            except socket.timeout:
                continue
            h = _parse_http_headers(data)
            key = (ip, h.get("USN", ""))
            if key not in seen:
                seen.add(key)
                out.append({"ip": ip, "st": h.get("ST", ""), "server": h.get("SERVER", ""),
                            "location": h.get("LOCATION", ""), "usn": h.get("USN", "")})
    except OSError:
        pass
    finally:
        s.close()
    return out


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def fetch_xml(url: str, timeout: float = 4) -> ET.Element | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return _strip_ns(ET.fromstring(r.read(1_000_000)))
    except Exception:
        return None


def upnp_describe(location: str) -> dict | None:
    """Read a UPnP device description: who made it, model, and the services it exposes."""
    root = fetch_xml(location)
    if root is None:
        return None
    dev = root.find("device")
    if dev is None:
        return None
    get = lambda el, tag: (el.findtext(tag) or "").strip()
    services = [
        {"type": get(s, "serviceType"), "control": get(s, "controlURL")}
        for s in root.iter("service")
    ]
    return {
        "location": location,
        "deviceType": get(dev, "deviceType"),
        "friendlyName": get(dev, "friendlyName"),
        "manufacturer": get(dev, "manufacturer"),
        "modelName": get(dev, "modelName"),
        "modelNumber": get(dev, "modelNumber"),
        "presentationURL": get(dev, "presentationURL"),
        "services": services,
    }
