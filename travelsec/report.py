"""Render reports to Markdown and save them (JSON + MD) under ~/.local/share/travelsec/reports."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .common import REPORT_DIR, Report

ICON = {"high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "info"}


def _ev(evidence: dict) -> str:
    if not evidence:
        return ""
    s = json.dumps(evidence, default=str)
    return s if len(s) < 400 else s[:400] + "…"


def to_markdown(rep: Report) -> str:
    d = rep.to_dict()
    out = [f"# travelsec {rep.mode} report{f' — {rep.label}' if rep.label else ''}", "", f"_{rep.started}_", ""]
    net = d["data"].get("network") or {}
    if net:
        out += [f"Network: **{net.get('ssid') or 'wired'}** ({net.get('security') or '-'}), "
                f"gateway {net.get('gateway')} [{net.get('gateway_mac')}], you are {net.get('address')}", ""]
    if v := d["data"].get("verdict"):
        out += [f"**Verdict:** {v}", ""]
    for scope, heading in (("network", "Findings"), ("device", "Your laptop")):
        fs = [f for f in d["findings"] if f["scope"] == scope]
        if scope == "device" and not fs:
            continue
        out += [f"## {heading}", ""]
        if not fs:
            out.append("Nothing notable.")
        for f in fs:
            out.append(f"- **[{ICON[f['severity']]}] {f['title']}**")
            if f["detail"]:
                out.append(f"  {f['detail']}")
            if ev := _ev(f["evidence"]):
                out.append(f"  `{ev}`")
        out.append("")
    if inv := d["data"].get("inventory"):
        out += ["", "## Device inventory", "", "| IP | Type | Name | Vendor | Open ports |", "|---|---|---|---|---|"]
        for x in inv:
            ports = ", ".join(f"{p['port']}{'/' + p['product'] if p['product'] else ''}" for p in x["ports"])
            name = ", ".join(x["names"])[:40] or x.get("rdns", "")
            out.append(f"| {x['ip']} | {x['type']} | {name} | {x['vendor']} | {ports} |")
    if ble := d["data"].get("ble_devices"):
        out += ["", "## Bluetooth devices heard", "", "| RSSI | Name | Kind | Company/Vendor | Address |", "|---|---|---|---|---|"]
        for b in ble[:40]:
            out.append(f"| {b['rssi']} | {b['name'] or ''} | {b['kind'] or ''} | {b['company'] or b['vendor'] or ''} | {b['mac']} ({b['addr_type']}) |")
    if aps := d["data"].get("wifi_aps"):
        out += ["", "## Wi-Fi networks heard (strongest first)", "", "| Signal | SSID | Vendor | Security |", "|---|---|---|---|"]
        for a in aps[:30]:
            out.append(f"| {a['signal']} ({a['distance']}) | {a['ssid'] or '(hidden)'} | {a['vendor']} | {a['security'] or 'open'} |")
    if clients := d["data"].get("clients"):
        out += ["", "## Per device", "", "| Client | Lookups | Flagged domains |", "|---|---|---|"]
        for ip, c in clients.items():
            out.append(f"| {ip} | {c['total']} | {', '.join(list(c['flagged'])[:6])} |")
    if cl := d["data"].get("physical_checklist"):
        out += ["", "## Physical check (do this too)", ""] + [f"{i}. {c}" for i, c in enumerate(cl, 1)]
    if d["notes"]:
        out += ["", "## Notes", ""] + [f"- {n}" for n in d["notes"]]
    return "\n".join(out) + "\n"


def save(rep: Report) -> tuple[Path, Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", rep.label.lower()).strip("-")
    stem = f"{rep.started.replace(':', '')}-{rep.mode}{'-' + slug if slug else ''}"
    jp, mp = REPORT_DIR / f"{stem}.json", REPORT_DIR / f"{stem}.md"
    jp.write_text(json.dumps(rep.to_dict(), indent=2, default=str))
    mp.write_text(to_markdown(rep))
    return jp, mp
