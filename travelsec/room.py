"""`travelsec room`: passive sweep of a hotel room / rental for cameras, mics, and trackers.

Listens only: Wi-Fi beacons, BLE advertisements, and broadcast announcements
on whatever network you've joined. Cross-references sightings across locations
so a tracker that follows you from place to place stands out.
"""

from __future__ import annotations

import datetime as dt
import re

from . import bluetooth, oui
from .common import DATA_DIR, Report, discovery_blocked_note, firewall, load_json, net_info, run, save_json, split_nmcli
from .discovery import arp_neighbors, mdns_browse, passive_listen

SIGHTINGS = DATA_DIR / "sightings.json"

# SSID patterns commonly used by camera setup hotspots and cheap Wi-Fi cameras
CAMERA_SSID = re.compile(
    r"(?i)(^ipc|ipcam|camera|[-_ ]cam\b|^cam[-_ \d]|hdwificam|minicam|lookcam|v380|wansview|^yi[-_ ]|wyze|"
    r"tapo_c|ezviz|^mv\d|\bspy|\bdvr\b|\bnvr\b)"
)
# Unconfigured smart devices broadcast setup hotspots like these
IOT_SSID = re.compile(r"(?i)(^ESP_|^MCU|^smart[_ ]?life|^tuya|^SL-|^ESP32|^AI-THINKER)")
BLE_COMPANIES = {0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google", 0x0171: "Amazon"}

PHYSICAL_CHECKLIST = [
    "Turn off the lights and slowly sweep the room with your phone's camera: many front cameras show IR LEDs as purple/white dots.",
    "Shine a flashlight across surfaces at eye level; camera lenses reflect a tight bright glint. Check smoke detectors, clocks, "
    "USB chargers, power strips, picture frames, air purifiers, TVs, set-top boxes, shelves facing the bed/shower.",
    "Look for small holes (1-3 mm) in objects facing the bed, shower, or toilet.",
    "Check outlets and USB chargers that seem out of place, or 'chargers' with no brand.",
    "Unplug or cover anything suspicious; disconnect the TV's power if you don't need it.",
    "Mirrors: with a fingertip touching the glass, a gap between finger and reflection means a normal mirror.",
    "If a device is a camera in a private area, photograph it, don't touch more than needed, and contact the host/platform and police.",
]


def _band(signal: int | None) -> str:
    if signal is None:
        return "?"
    return "very close" if signal >= 75 else "nearby" if signal >= 50 else "distant"


def scan_wifi(rep: Report) -> None:
    out = run(["nmcli", "-t", "-f", "SSID,BSSID,SECURITY,SIGNAL,CHAN,FREQ", "dev", "wifi", "list", "--rescan", "yes"], timeout=30)
    aps = []
    for p in (split_nmcli(l) for l in out.splitlines()):
        if len(p) < 6:
            continue
        ssid, bssid, sec, sig, chan, freq = p[:6]
        sig_i = int(sig) if sig.isdigit() else None
        info = oui.describe(bssid)
        ap = {"ssid": ssid, "bssid": bssid, "security": sec, "signal": sig_i, "channel": chan,
              "distance": _band(sig_i), **{k: info[k] for k in ("vendor", "category")}}
        aps.append(ap)
        close = (sig_i or 0) >= 60
        if CAMERA_SSID.search(ssid or ""):
            rep.add("high" if close else "medium", f"Camera-style Wi-Fi network: '{ssid}' ({ap['distance']})",
                    "Many cheap cameras broadcast setup or direct-connect hotspots with names like this. "
                    "Strong signal = probably in or next to your room.", **ap)
        elif IOT_SSID.search(ssid or "") and close:
            rep.add("medium", f"IoT setup hotspot nearby: '{ssid}'",
                    "An unconfigured smart gadget (plug, camera, sensor). Worth locating if it's in your room.", **ap)
        elif info["category"] == "camera":
            rep.add("high" if close else "medium", f"Access point from a camera maker: {info['vendor']}", **ap)
        elif info["category"] == "iot-module" and close:
            rep.add("medium", f"Nearby IoT-chip hotspot ({info['vendor']})",
                    "Wi-Fi modules used in cheap cameras, plugs and gadgets. Worth locating.", **ap)
        elif not ssid and close:
            rep.add("low", "Hidden Wi-Fi network very close",
                    "Hidden networks near you can be private camera/IoT links. Usually benign.", **ap)
    rep.data["wifi_aps"] = sorted(aps, key=lambda a: -(a["signal"] or 0))
    if not aps:
        rep.note("Wi-Fi scan returned nothing (is Wi-Fi on?).")


def scan_ble(rep: Report, seconds: int) -> list[dict]:
    devices, err = bluetooth.scan(seconds)
    if err:
        rep.note(f"Bluetooth: {err}")
        return []
    for d in devices:
        comp = next((BLE_COMPANIES.get(int(k, 16)) for k in d.get("manufacturer", {}) if k.startswith("0x")), None)
        d["company"] = comp
        if d.get("addr_type") == "public":
            d["vendor"] = oui.vendor(d["mac"])
        if d["kind"] and d["severity"] != "info":
            label = d.get("name") or d.get("alias") or d["mac"]
            rep.add(d["severity"], f"Bluetooth: {d['kind']} — {label} (RSSI {d.get('rssi')})", d["why"],
                    mac=d["mac"], rssi=d.get("rssi"), name=d.get("name"))
    rep.data["ble_devices"] = [
        {k: d.get(k) for k in ("mac", "name", "rssi", "kind", "company", "vendor", "icon", "addr_type")} for d in devices
    ]
    return devices


def scan_lan(rep: Report, net, listen_seconds: int) -> None:
    """On the network you've been given (hotel/rental Wi-Fi): listen for cameras announcing themselves."""
    if not net.gateway:
        rep.note("Not connected to a network; skipped LAN listening.")
        return
    services = mdns_browse(timeout=10)
    for s in services:
        if s["category"] == "camera":
            rep.add("high", f"Camera service on this network: {s['name']} ({s['type']})",
                    "A device on the room's network advertises a video stream.", ip=s["ip"], host=s["host"])
        elif s["category"] in ("smart-home", "tv/streaming", "speaker"):
            rep.add("info", f"{s['description']}: {s['name']}", ip=s["ip"])
    heard = passive_listen(listen_seconds)
    for w in heard["wsd"]:
        if w["onvif"]:
            rep.add("high", f"ONVIF camera announced itself at {w['ip']}", "ONVIF is the standard IP-camera protocol.", ip=w["ip"])
    for n in heard["ssdp"]:
        if re.search(r"(?i)camera|ipc|nvr|dvr|hikvision|dahua", n["nt"] + n["server"]):
            rep.add("high", f"UPnP camera/recorder at {n['ip']}", **n)
    neigh = [{**n, **oui.describe(n["mac"])} for n in arp_neighbors(net.iface)]
    for n in neigh:
        if n["category"] == "camera":
            rep.add("high", f"Camera-maker device on this network: {n['vendor']} at {n['ip']}", **n)
    if not services and not heard["ssdp"] and (note := discovery_blocked_note(firewall())):
        rep.note(note)
    rep.data["lan"] = {"mdns": services, "ssdp_notify": heard["ssdp"], "wsd": heard["wsd"],
                       "arp_cache": neigh, "listen_errors": heard["errors"]}


def track_sightings(rep: Report, ble: list[dict], label: str) -> None:
    """Remember trackers and stable-MAC devices per location; flag anything that follows you."""
    if not label:
        rep.note("No --label given; skipped cross-location tracker check.")
        return
    db = load_json(SIGHTINGS, {})
    now = dt.datetime.now().isoformat(timespec="seconds")
    for d in ble:
        tracker = d["kind"] in ("findmy-separated", "tracker")
        stable = d.get("addr_type") == "public"
        if not (tracker or stable):
            continue  # rotating random addresses can't be matched across places
        rec = db.setdefault(d["mac"], {"name": d.get("name"), "kind": d["kind"], "seen": []})
        rec["seen"].append({"label": label, "at": now, "rssi": d.get("rssi")})
        places = sorted({s["label"] for s in rec["seen"]})
        if tracker and len(places) >= 2:
            rep.add("high", f"Tracker seen at {len(places)} of your locations: {d.get('name') or d['mac']}",
                    "The same tracker has been near you in different places. Find it (phone tracker-detect apps "
                    "can make it play a sound) and consider contacting police.", places=places, mac=d["mac"])
    # keep the file from growing forever
    for rec in db.values():
        rec["seen"] = rec["seen"][-50:]
    save_json(SIGHTINGS, db)


def run_room(label: str = "", ble_seconds: int = 30, listen_seconds: int = 20) -> Report:
    rep = Report("room", label=label)
    net = net_info()
    rep.data["network"] = {k: v for k, v in vars(net).items()}
    scan_wifi(rep)
    ble = scan_ble(rep, ble_seconds)
    scan_lan(rep, net, listen_seconds)
    track_sightings(rep, ble, label)
    rep.data["physical_checklist"] = PHYSICAL_CHECKLIST
    return rep
