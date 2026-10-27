"""`travelsec dns-log`: classify the domains in a router / Pi-hole / AdGuard DNS query log.

A laptop on Wi-Fi can't see a TV's traffic, but the DNS log on your router can.
This turns that log into "which device is talking to which tracking service".
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from .common import DATA_DIR, Report

# Hand-curated starting list. Suffix match: "x.samsungacr.com" matches "samsungacr.com".
# Extend it with your own entries in ~/.local/share/travelsec/trackers.txt ("domain category" per line).
KNOWN: dict[str, str] = {
    # Automatic content recognition: the TV fingerprints what's on screen and reports it
    "samsungacr.com": "tv-acr", "samba.tv": "tv-acr", "alphonso.tv": "tv-acr", "tvinteractive.tv": "tv-acr",
    # TV / streaming platform telemetry and ads
    "samsungads.com": "tv-ads", "samsungcloudsolution.com": "tv-telemetry", "lgsmartad.com": "tv-ads",
    "lgtvsdp.com": "tv-telemetry", "logs.roku.com": "tv-telemetry", "ads.roku.com": "tv-ads",
    "device-metrics-us.amazon.com": "device-telemetry", "device-metrics-us-2.amazon.com": "device-telemetry",
    # Mobile/app analytics and ad networks
    "doubleclick.net": "ads", "googlesyndication.com": "ads", "googleadservices.com": "ads",
    "app-measurement.com": "analytics", "firebaselogging-pa.googleapis.com": "analytics",
    "graph.facebook.com": "analytics", "scorecardresearch.com": "analytics", "appsflyer.com": "analytics",
    "adjust.com": "analytics", "branch.io": "analytics", "mixpanel.com": "analytics", "amplitude.com": "analytics",
    "segment.io": "analytics", "crashlytics.com": "analytics",
    # IoT clouds: not tracking per se, but shows where cameras/plugs send data
    "tuyaus.com": "iot-cloud", "tuyaeu.com": "iot-cloud", "tuyacn.com": "iot-cloud",
    "hik-connect.com": "iot-cloud", "ezvizlife.com": "iot-cloud",
}
EXTRA = DATA_DIR / "trackers.txt"
BLOCKLIST = DATA_DIR / "blocklist-hosts.txt"  # StevenBlack hosts, via scripts/fetch-data.sh

DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
CLIENT = re.compile(r"\b(?:from|client[=:]?)\s*((?:\d{1,3}\.){3}\d{1,3})", re.I)


def _load() -> tuple[dict[str, str], set[str]]:
    known = dict(KNOWN)
    if EXTRA.exists():
        for line in EXTRA.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"):
                known[parts[0].lower()] = parts[1]
    block: set[str] = set()
    if BLOCKLIST.exists():
        for line in BLOCKLIST.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                block.add(parts[1].lower())
    return known, block


def classify(domain: str, known: dict[str, str], block: set[str]) -> str | None:
    labels = domain.lower().split(".")
    for i in range(len(labels) - 1):
        suffix = ".".join(labels[i:])
        if suffix in known:
            return known[suffix]
    return "blocklist" if domain.lower() in block else None


def run_dnslog(paths: list[str]) -> Report:
    rep = Report("dns-log")
    known, block = _load()
    if not block:
        rep.note("No blocklist found; only the built-in list is used. Run scripts/fetch-data.sh for broader coverage.")
    counts: Counter[str] = Counter()
    by_client: dict[str, Counter[str]] = defaultdict(Counter)
    for p in paths:
        for line in Path(p).read_text(errors="replace").splitlines():
            doms = [d for d in DOMAIN.findall(line) if not d.lower().endswith((".arpa", ".local", ".lan", ".home"))]
            if not doms:
                continue
            d = doms[0].lower()
            counts[d] += 1
            if m := CLIENT.search(line):
                by_client[m.group(1)][d] += 1

    flagged = {d: classify(d, known, block) for d in counts}
    flagged = {d: c for d, c in flagged.items() if c}
    cats: dict[str, Counter[str]] = defaultdict(Counter)
    for d, c in flagged.items():
        cats[c][d] = counts[d]
    for cat, ctr in sorted(cats.items()):
        sev = "medium" if cat == "tv-acr" else "low" if cat in ("tv-ads", "tv-telemetry", "device-telemetry") else "info"
        rep.add(sev, f"{cat}: {sum(ctr.values())} lookups to {len(ctr)} domain(s)",
                "TV ACR = your TV reports what you watch. Turn off 'Viewing information', 'Live Plus', "
                "'Smart Interactivity' or similar in the TV's privacy settings, or block these domains."
                if cat == "tv-acr" else "", top=dict(ctr.most_common(10)))
    rep.data["top_domains"] = dict(counts.most_common(40))
    rep.data["clients"] = {
        ip: {"total": sum(c.values()),
             "flagged": {d: n for d, n in c.most_common() if d in flagged},
             "top": dict(c.most_common(15))}
        for ip, c in sorted(by_client.items(), key=lambda kv: -sum(kv[1].values()))
    }
    if not by_client:
        rep.note("Couldn't find client IPs in the log lines, so results aren't split per device.")
    return rep
