"""BLE / Bluetooth sweep via bluetoothctl: what's advertising near me, and is any of it a tracker?"""

from __future__ import annotations

import re
import subprocess
import threading
import time

from .common import have, run

APPLE = 0x004C
# 16-bit service UUIDs used by item-tracker networks
TRACKER_UUIDS = {
    "feed": "Tile tracker",
    "feec": "Tile tracker",
    "fd5a": "Samsung SmartTag",
}
CAMERA_NAME = re.compile(r"(?i)\b(cam|camera|ipc|dvr|nvr|spy|lookcam|v380|hdcam|minicam|ezviz|wyze|yi[-_ ]?home)")


def adapter_powered() -> bool | None:
    out = run(["bluetoothctl", "show"], timeout=10)
    if not out:
        return None
    return "Powered: yes" in out


_HEX_LINE = re.compile(r"^  ((?:[0-9a-f]{2} ?)+)")


def _hex_after(lines: list[str], j: int) -> tuple[str, int]:
    """Collect the hex dump lines that bluetoothctl prints under a *.Value / ServiceData key."""
    out = []
    while j < len(lines) and (m := _HEX_LINE.match(lines[j][:50])):
        out += m.group(1).split()
        j += 1
    return "".join(out), j


def parse_info(text: str) -> dict:
    """Parse `bluetoothctl info <mac>` output."""
    d: dict = {"manufacturer": {}, "uuids": [], "service_data": {}}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        i += 1
        if m := re.match(r"Device ([0-9A-F:]{17})(?: \((\w+)\))?", s):
            d["mac"], d["addr_type"] = m.group(1), m.group(2) or ""
        elif s.startswith("Name:"):
            d["name"] = s[5:].strip()
        elif s.startswith("Alias:"):
            d["alias"] = s[6:].strip()
        elif s.startswith("RSSI:") and (m := re.search(r"\((-?\d+)\)|(-\d+)", s)):
            d["rssi"] = int(m.group(1) or m.group(2))
        elif s.startswith(("Paired:", "Connected:")):
            d[s.split(":")[0].lower()] = s.endswith("yes")
        elif s.startswith("Icon:"):
            d["icon"] = s[5:].strip()
        elif s.startswith("Modalias:"):
            d["modalias"] = s[9:].strip()
        elif s.startswith("UUID:") and (m := re.search(r"\(([0-9a-f-]{36})\)", s)):
            d["uuids"].append(m.group(1))
        elif s.startswith("ManufacturerData.Key:"):
            key = s.split(":", 1)[1].split()[0]
            if i < len(lines) and lines[i].strip() == "ManufacturerData.Value:":
                i += 1
            d["manufacturer"][key], i = _hex_after(lines, i)
        elif s.startswith("ServiceData."):
            uuid = s[len("ServiceData."):].rstrip(":")
            d["service_data"][uuid], i = _hex_after(lines, i)
    return d


def parse_scan_stream(text: str) -> dict[str, dict]:
    """Parse live `bluetoothctl scan on` events: strongest RSSI and manufacturer data per device."""
    devs: dict[str, dict] = {}
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in text.splitlines()]
    i = 0
    while i < len(lines):
        m = re.match(r"\[(?:NEW|CHG)\] Device ([0-9A-F:]{17}) (.*)", lines[i].strip())
        i += 1
        if not m:
            continue
        d = devs.setdefault(m.group(1), {"manufacturer": {}})
        rest = m.group(2)
        if rest.startswith("RSSI:") and (r := re.search(r"\((-?\d+)\)|(-\d+)", rest)):
            v = int(r.group(1) or r.group(2))
            d["rssi"] = max(v, d.get("rssi", -127))
        elif rest.startswith("ManufacturerData.Key:"):
            d["_key"] = rest.split(":", 1)[1].split()[0]
        elif rest.startswith("ManufacturerData.Value:") and "_key" in d:
            d["manufacturer"][d.pop("_key")], i = _hex_after(lines, i)
    return devs


def _short_uuid(u: str) -> str | None:
    m = re.match(r"0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb", u.lower())
    return m.group(1) if m else None


def classify(dev: dict) -> tuple[str | None, str, str]:
    """Return (kind, severity, explanation) for a BLE device."""
    for key, hexdata in dev.get("manufacturer", {}).items():
        try:
            company = int(key, 16)
        except ValueError:
            continue
        if company == APPLE and hexdata.startswith("12"):
            # Find My "offline finding" advertisement. Length byte 0x19 = full key, sent when the
            # accessory has been away from its owner for a while (the AirTag stalking case).
            if hexdata[2:4] == "19":
                return ("findmy-separated", "high",
                        "Apple Find My accessory separated from its owner (AirTag-style). If it shows up in "
                        "several places you go, someone may be tracking you. iPhone/Android 'unknown tracker' "
                        "alerts can make it beep.")
            return ("findmy-nearby-owner", "info", "Apple Find My device near its owner (normal).")
    for u in dev.get("uuids", []) + list(dev.get("service_data", {})):
        short = _short_uuid(u)
        if short in TRACKER_UUIDS:
            return ("tracker", "medium", f"{TRACKER_UUIDS[short]}. Normal if it's a fellow guest's keys; "
                                        "worrying if it keeps appearing wherever you go.")
    name = dev.get("name") or dev.get("alias") or ""
    if CAMERA_NAME.search(name):
        return ("camera-like", "high" if (dev.get("rssi") or -100) > -70 else "medium",
                f"Device name '{name}' looks like a camera/DVR. Strong signal means it's close.")
    return (None, "info", "")


def scan(seconds: int = 25) -> tuple[list[dict], str | None]:
    """Run a BLE/BR-EDR discovery and return devices actually seen in this scan."""
    if not have("bluetoothctl"):
        return [], "bluetoothctl not installed"
    powered = adapter_powered()
    if powered is None:
        return [], "no Bluetooth adapter found"
    if not powered:
        return [], "Bluetooth adapter is off (run `bluetoothctl power on` and re-run)"
    # Keep discovery running while we read `info`: BlueZ drops RSSI as soon as scanning stops,
    # and brand-new devices only get a [NEW] line (no RSSI) in the event stream.
    proc = subprocess.Popen(["bluetoothctl", "--timeout", str(seconds + 60), "scan", "on"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    chunks: list[str] = []
    reader = threading.Thread(target=lambda: chunks.extend(proc.stdout), daemon=True)
    reader.start()
    time.sleep(seconds)
    infos = {}
    for line in run(["bluetoothctl", "devices"]).splitlines():
        if m := re.match(r"Device ([0-9A-F:]{17})", line):
            infos[m.group(1)] = parse_info(run(["bluetoothctl", "info", m.group(1)], timeout=10))
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    run(["bluetoothctl", "scan", "off"], timeout=10)
    reader.join(timeout=2)
    live = parse_scan_stream("".join(chunks))
    for mac, info in infos.items():
        seen = live.setdefault(mac, {"manufacturer": {}})
        if info.get("rssi") is not None:
            seen["rssi"] = max(info["rssi"], seen.get("rssi", -127))
        seen["info"] = info
    devices = []
    for mac, seen in live.items():
        if "rssi" not in seen:
            continue  # only property changes, no advertisement heard this scan
        info = seen.get("info") or parse_info(run(["bluetoothctl", "info", mac], timeout=10))
        info.setdefault("mac", mac)
        info["rssi"] = seen["rssi"]
        info["manufacturer"] = {**info.get("manufacturer", {}), **seen["manufacturer"]}
        kind, sev, why = classify(info)
        info.update(kind=kind, severity=sev, why=why)
        devices.append(info)
    devices.sort(key=lambda d: -(d.get("rssi") or -127))
    return devices, None
