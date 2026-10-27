"""travelsec command line."""

from __future__ import annotations

import argparse
import json
import sys

from . import report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="travelsec", description="Personal surveillance & network-privacy audits.")
    ap.add_argument("--json", action="store_true", help="print the full JSON report instead of Markdown")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wifi", help="check what the current network does to your traffic (safe anywhere)")
    w.add_argument("--label", default="", help="name for this place, e.g. 'blue bottle sf'")
    w.add_argument("--baseline", action="store_true", help="record TLS issuers as trusted (run on a network you trust)")

    r = sub.add_parser("room", help="passive sweep for cameras, trackers and IoT around you (safe anywhere)")
    r.add_argument("--label", default="", help="name for this place; enables cross-location tracker detection")
    r.add_argument("--ble-seconds", type=int, default=30)
    r.add_argument("--listen-seconds", type=int, default=20)

    h = sub.add_parser("home", help="active inventory + audit of a network YOU OWN")
    h.add_argument("--i-own-this-network", dest="confirm", action="store_true",
                   help="confirm you own / are authorized to scan this network (remembered by router MAC)")
    h.add_argument("--full", action="store_true", help="scan nmap's top 1000 ports instead of the curated list")
    h.add_argument("--force", action="store_true", help="allow networks larger than /22")

    d = sub.add_parser("dns-log", help="classify domains in a router / Pi-hole / AdGuard DNS log")
    d.add_argument("files", nargs="+")

    a = ap.parse_args(argv)
    if a.cmd == "wifi":
        from .wifi import run_wifi
        rep = run_wifi(a.label, a.baseline)
    elif a.cmd == "room":
        from .room import run_room
        rep = run_room(a.label, a.ble_seconds, a.listen_seconds)
    elif a.cmd == "home":
        from .home import run_home
        rep = run_home(a.confirm, a.full, a.force)
    else:
        from .dnslog import run_dnslog
        rep = run_dnslog(a.files)

    jp, mp = report.save(rep)
    print(json.dumps(rep.to_dict(), indent=2, default=str) if a.json else report.to_markdown(rep))
    print(f"\nSaved: {mp}\n       {jp}", file=sys.stderr)
    return 2 if rep.data.get("refused") else 0
