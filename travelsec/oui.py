"""MAC address -> vendor lookup and coarse device-category hints.

Vendor data comes from files already on the system (hwdata, nmap) or the IEEE
CSV that scripts/fetch-data.sh downloads. Nothing is hardcoded by prefix, since
a wrong prefix would cause false alarms.
"""

from __future__ import annotations

import csv
import re
from functools import lru_cache
from pathlib import Path

from .common import DATA_DIR

SOURCES = [
    DATA_DIR / "oui.csv",                      # IEEE MA-L CSV
    Path("/usr/share/hwdata/oui.txt"),         # hwdata (Arch/Fedora)
    Path("/usr/share/ieee-data/oui.txt"),      # Debian/Ubuntu
    Path("/usr/share/nmap/nmap-mac-prefixes"),
]

# Keyword -> category. Matched case-insensitively against the vendor name.
# These say which vendors *commonly make* a device type. They are hints, not proof.
CATEGORIES: dict[str, list[str]] = {
    "camera": [
        "hikvision", "dahua", "ezviz", "uniview", "reolink", "wyze", "amcrest", "foscam",
        "wansview", "arlo", "axis communications", "hanwha", "vivotek", "lorex", "swann",
        "yi technology", "eufy", "ring llc", "blink", "imou", "annke", "tiandy",
    ],
    "iot-module": [
        # Cheap Wi-Fi chips used in no-name cameras, plugs, and bulbs
        "espressif", "tuya", "beken", "bouffalo", "gaoshengda", "bilian", "hi-flying",
        "realtek semiconductor", "mediatek", "amlogic", "ingenic", "anyka", "xiongmai",
        "fn-link", "azurewave", "cypress", "silicon labs",
    ],
    "tv/streaming": [
        "samsung", "lg electronics", "vizio", "roku", "tcl", "hisense", "sony",
        "amazon technologies", "google", "nvidia", "philips", "sharp", "funai",
    ],
    "router/network": [
        "tp-link", "netgear", "ubiquiti", "cisco", "aruba", "ruckus", "mikrotik", "asus",
        "linksys", "eero", "huawei", "zte", "arris", "sagemcom", "technicolor", "fortinet",
        "cambium", "juniper", "d-link", "gl technologies", "nokia",
    ],
}


def normalize(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: a privacy MAC (phones/laptops), so the vendor is unknown."""
    m = normalize(mac)
    return len(m) >= 2 and bool(int(m[:2], 16) & 0x02)


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    for src in SOURCES:
        if not src.exists():
            continue
        if src.suffix == ".csv":
            with src.open(newline="", encoding="utf-8", errors="replace") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and len(row[1]) == 6:
                        table.setdefault(row[1].upper(), row[2].strip())
        else:
            for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^([0-9A-Fa-f]{6})\s+(?:\(base 16\)\s+)?(.+)$", line.strip())
                if m:
                    table.setdefault(m.group(1).upper(), m.group(2).strip())
    return table


def vendor(mac: str) -> str | None:
    if not mac or is_randomized(mac):
        return None
    return _table().get(normalize(mac)[:6])


def category(vendor_name: str | None) -> str | None:
    if not vendor_name:
        return None
    v = vendor_name.lower()
    for cat, words in CATEGORIES.items():
        if any(w in v for w in words):
            return cat
    return None


def describe(mac: str) -> dict:
    v = vendor(mac)
    return {
        "mac": mac,
        "vendor": v or ("randomized (private MAC)" if is_randomized(mac) else "unknown"),
        "category": category(v),
    }
