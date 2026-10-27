"""Shared helpers: findings/report model, subprocess wrapper, local network facts."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

DATA_DIR = Path(os.environ.get("TRAVELSEC_HOME", Path.home() / ".local/share/travelsec"))
REPORT_DIR = DATA_DIR / "reports"

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    evidence: dict = field(default_factory=dict)
    scope: str = "network"  # "network" = about the place you're in; "device" = about your own laptop


@dataclass
class Report:
    mode: str
    label: str = ""
    started: str = field(default_factory=lambda: dt.datetime.now().isoformat(timespec="seconds"))
    findings: list[Finding] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, severity: str, title: str, detail: str = "", *, scope: str = "network", **evidence) -> None:
        assert severity in SEVERITIES, severity
        self.findings.append(Finding(severity, title, detail, evidence, scope))

    def note(self, text: str) -> None:
        """Something the scan couldn't do (missing tool, permission, etc.)."""
        self.notes.append(text)

    def worst(self, scope: str = "network") -> str:
        sevs = [f.severity for f in self.findings if f.scope == scope]
        return max(sevs, key=SEVERITIES.index) if sevs else "info"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"].sort(key=lambda f: -SEVERITIES.index(f["severity"]))
        return d


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd: list[str], timeout: float = 30) -> str:
    """Run a command and return stdout, or "" if it fails or is missing."""
    if not have(cmd[0]):
        return ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return p.stdout


def is_root() -> bool:
    return os.geteuid() == 0


def firewall() -> dict:
    """Best-effort host firewall state without root: which firewall is active and its default inbound policy."""
    for name in ("ufw", "firewalld", "nftables"):
        if run(["systemctl", "is-active", name], timeout=5).strip() == "active":
            policy = ""
            if name == "ufw":
                try:
                    m = re.search(r'^DEFAULT_INPUT_POLICY="?(\w+)', Path("/etc/default/ufw").read_text(), re.M)
                    policy = m.group(1) if m else ""
                except OSError:
                    pass
            return {"name": name, "inbound_default": policy}
    return {"name": None, "inbound_default": ""}


def discovery_blocked_note(fw: dict) -> str | None:
    if fw["name"] and not is_root():
        return (f"Host firewall ({fw['name']}) is active and likely drops replies to LAN discovery (mDNS/SSDP), "
                "so device lists may be empty. For a fuller scan, run via `sudo scripts/with-discovery.sh <mode> ...`, "
                "which opens a temporary inbound-UDP rule for the local subnet only.")
    return None


def run_json(cmd: list[str], timeout: float = 30):
    out = run(cmd, timeout)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        return None


def split_nmcli(line: str) -> list[str]:
    """Split `nmcli -t` output, which escapes literal colons as `\\:`."""
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified


@dataclass
class NetInfo:
    iface: str = ""
    gateway: str = ""
    gateway_mac: str = ""
    address: str = ""
    cidr: str = ""
    ssid: str = ""
    bssid: str = ""
    security: str = ""
    signal: int | None = None
    channel: str = ""
    dns_servers: list[str] = field(default_factory=list)

    @property
    def is_wifi(self) -> bool:
        return bool(self.ssid or self.bssid)


def net_info() -> NetInfo:
    info = NetInfo()
    routes = run_json(["ip", "-j", "route", "show", "default"]) or []
    if routes:
        info.iface = routes[0].get("dev", "")
        info.gateway = routes[0].get("gateway", "")
    if info.iface:
        for a in run_json(["ip", "-j", "addr", "show", "dev", info.iface]) or []:
            for ai in a.get("addr_info", []):
                if ai.get("family") == "inet":
                    info.address = ai["local"]
                    info.cidr = str(ipaddress.ip_interface(f"{ai['local']}/{ai['prefixlen']}").network)
                    break
    if info.gateway:
        for n in run_json(["ip", "-j", "neigh", "show", info.gateway]) or []:
            info.gateway_mac = n.get("lladdr", "")
    for line in run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SECURITY,SIGNAL,CHAN", "dev", "wifi"]).splitlines():
        parts = split_nmcli(line)
        if len(parts) >= 6 and parts[0] == "yes":
            info.ssid, info.bssid, info.security, sig, info.channel = parts[1:6]
            info.signal = int(sig) if sig.isdigit() else None
            break
    if info.iface:
        for line in run(["nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "dev", "show", info.iface]).splitlines():
            _, _, val = line.partition(":")
            if val:
                info.dns_servers.append(val.replace("\\:", ":"))
    return info


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True))
