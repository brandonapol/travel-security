"""`travelsec wifi`: what is this network doing to *my* traffic?

Every test here inspects your own connection: requests you make, answers you
get back, and what your own laptop exposes. Nothing probes other people's
devices or the operator's equipment.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request

from . import dnsclient
from .common import (DATA_DIR, Report, discovery_blocked_note, firewall, is_private, load_json, net_info, run,
                     save_json, split_nmcli)
from .discovery import mdns_browse

BASELINE = DATA_DIR / "tls-baseline.json"
TLS_HOSTS = ["www.google.com", "github.com", "www.cloudflare.com", "en.wikipedia.org", "www.apple.com", "login.microsoftonline.com"]
DNS_CHECK_DOMAINS = ["github.com", "www.wikipedia.org", "www.apple.com"]
UA = "Mozilla/5.0 (X11; Linux x86_64) travelsec"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _get(url: str, timeout: float = 8) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(2_000_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(200_000)


# --- individual checks -------------------------------------------------------------

def check_link(rep: Report, net) -> None:
    sec = (net.security or "").upper()
    if not net.is_wifi:
        rep.add("info", "Not on Wi-Fi", "Wired or tethered connection; link-layer checks skipped.")
        return
    if sec in ("", "--"):
        rep.add("high", "Open Wi-Fi (no encryption)",
                "Anyone in radio range can passively read every unencrypted packet you send, "
                "and the network can't prove it's the real hotspot. Use a VPN.", ssid=net.ssid)
    elif "WEP" in sec:
        rep.add("high", "WEP encryption (broken since 2001)", "Treat as open Wi-Fi.", ssid=net.ssid)
    elif "WPA1" in sec and "WPA2" not in sec:
        rep.add("medium", "WPA1 encryption (obsolete)", ssid=net.ssid)
    elif "802.1X" in sec:
        rep.add("info", "Enterprise Wi-Fi (802.1X)", "Per-user keys; other users can't decrypt your traffic.")
    elif "WPA3" in sec or "SAE" in sec:
        rep.add("info", "WPA3", "Per-session keys; other users who know the password can't decrypt your traffic.")
    else:
        rep.add("low", "WPA2-Personal with a shared password",
                "Anyone who knows the password (every other customer) can decrypt your traffic "
                "if they capture you joining, or run a look-alike hotspot. HTTPS still protects page contents.",
                security=net.security)


def check_evil_twin(rep: Report, net) -> None:
    """Same SSID advertised with different security settings is a classic rogue-AP sign."""
    if not net.ssid:
        return
    out = run(["nmcli", "-t", "-f", "SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list"], timeout=20)
    aps = [p for p in (split_nmcli(l) for l in out.splitlines()) if len(p) >= 4 and p[0] == net.ssid]
    rep.data["same_ssid_aps"] = [{"bssid": b, "security": s, "signal": g} for _, b, s, g in aps]
    secs = {(s or "open") for _, _, s, _ in aps}
    if len(secs) > 1:
        rep.add("high", f"Multiple '{net.ssid}' networks with different security",
                "Someone may be running a look-alike (evil twin) hotspot. Confirm the correct one with staff; "
                "prefer the encrypted one; use a VPN.", variants=sorted(secs))


def check_captive_portal(rep: Report) -> bool:
    try:
        status, headers, _ = _get("http://connectivitycheck.gstatic.com/generate_204")
    except Exception as e:
        rep.add("medium", "Connectivity check failed", str(e))
        return True
    rep.data["captive_check"] = {"status": status, "location": headers.get("Location", "")}
    if status == 204:
        return False
    rep.add("medium", "Captive portal or HTTP interception active",
            "Plain HTTP requests are being answered or redirected by the network rather than the real site. "
            "Finish the portal login and re-run; results below may be skewed.",
            status=status, redirect=headers.get("Location", ""))
    return True


def check_http_tampering(rep: Report) -> None:
    """Fetch the same page over HTTP and HTTPS. Any difference was injected in transit."""
    try:
        _, h_http, b_http = _get("http://example.com/")
        _, _, b_https = _get("https://example.com/")
    except Exception as e:
        rep.note(f"HTTP tamper check skipped: {e}")
        return
    if b_http != b_https:
        injected = re.findall(rb"<(?:script|iframe)[^>]*>", b_http)
        rep.add("high" if injected else "medium", "Network modified a plain-HTTP page",
                "The page fetched over HTTP differs from the HTTPS copy, so content is being injected or rewritten "
                "(ads, tracking scripts, or worse). Avoid any non-HTTPS site here.",
                injected_tags=[t.decode(errors='replace')[:200] for t in injected[:5]],
                http_sha256=hashlib.sha256(b_http).hexdigest(), https_sha256=hashlib.sha256(b_https).hexdigest())
    proxy_hdrs = {k: v for k, v in h_http.items() if k.lower() in ("via", "x-cache", "x-squid-error", "x-bluecoat-via")}
    if proxy_hdrs:
        rep.add("low", "Transparent HTTP proxy in path", "Your HTTP traffic passes through a proxy run by the network.",
                headers=proxy_hdrs)

    # What does a server see of our HTTP request? Extra headers = injected identifiers.
    try:
        _, _, body = _get("http://httpbin.org/headers")
        seen = json.loads(body).get("headers", {})
    except Exception:
        return
    sent = {"Host", "User-Agent", "Accept-Encoding", "Connection", "X-Amzn-Trace-Id"}
    extra = {k: v for k, v in seen.items() if k not in sent}
    if extra:
        rep.add("medium", "Network adds headers to your HTTP requests",
                "Injected headers can carry a subscriber ID that tracks you across sites (a 'supercookie').",
                headers=extra)


def check_dns(rep: Report, net) -> None:
    rep.data["dns_servers"] = net.dns_servers
    if net.dns_servers:
        rep.add("info", "Network-provided DNS can log every site you visit",
                "Unless you use DNS-over-HTTPS or a VPN, the operator sees each domain you look up.",
                servers=net.dns_servers)

    # 1. Do nonexistent domains resolve? (NXDOMAIN hijacking for ads/tracking)
    bogus = dnsclient.random_nonexistent()
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(bogus, 80, socket.AF_INET)})
    except socket.gaierror:
        ips = []
    if ips:
        rep.add("medium", "DNS hijacking: nonexistent domains resolve",
                "Typos get redirected to the operator's page instead of failing. Your lookups are being rewritten.",
                domain=bogus, answers=ips)

    # 2. Transparent interception: send a DNS query to an address with no DNS server.
    #    192.0.2.1 is TEST-NET-1 (RFC 5737), unroutable. Any reply was forged by the network.
    fake = dnsclient.query("192.0.2.1", "example.com", timeout=2)
    if fake is not None:
        rep.add("high", "DNS traffic is transparently intercepted",
                "A DNS query sent to an address with no DNS server got an answer, so the network captures all port-53 "
                "traffic regardless of which resolver you choose. Use DoH/DoT or a VPN.", answer=fake.records)

    # 3. Ask Cloudflare who it is. A hijacking middlebox can't answer this correctly.
    cf = dnsclient.query("1.1.1.1", "id.server", "TXT", dnsclient.CLASS_CH)
    rep.data["cloudflare_id_server"] = cf.records if cf else None
    if cf is not None and not cf.values("TXT"):
        rep.add("medium", "Queries to 1.1.1.1 are answered by something else",
                "1.1.1.1 didn't return its normal server identity; DNS is likely redirected.", rcode=cf.rcode)
    cf_bogus = dnsclient.query("1.1.1.1", dnsclient.random_nonexistent())
    if cf_bogus and cf_bogus.values("A"):
        rep.add("high", "Direct DNS to 1.1.1.1 is rewritten", answers=cf_bogus.values("A"))

    # 4. Compare the system resolver against DoH (which the network can't rewrite).
    compare = {}
    for d in DNS_CHECK_DOMAINS:
        try:
            sys_ips = sorted({ai[4][0] for ai in socket.getaddrinfo(d, 443, socket.AF_INET)})
        except socket.gaierror:
            sys_ips = []
        trusted = dnsclient.doh(d)
        compare[d] = {"system": sys_ips, "doh": trusted.values("A") if trusted else None}
        bad = [ip for ip in sys_ips if is_private(ip)]
        if bad:
            rep.add("high", f"{d} resolves to a private address", "Classic DNS spoofing to a local machine.",
                    domain=d, answers=sys_ips)
    rep.data["dns_compare"] = compare
    if all(v["doh"] is None for v in compare.values()):
        rep.add("low", "DNS-over-HTTPS appears blocked", "Can't reach cloudflare-dns.com; the network may be forcing its own DNS.")

    # 5. Is encrypted DNS (DoT) reachable?
    try:
        socket.create_connection(("1.1.1.1", 853), timeout=3).close()
        rep.data["dot_reachable"] = True
    except OSError:
        rep.data["dot_reachable"] = False
        rep.add("low", "DNS-over-TLS (port 853) blocked", "Encrypted DNS options are limited; DoH or a VPN may still work.")


def _openssl_names(der: bytes) -> dict:
    try:
        out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-issuer", "-subject"],
                             input=der, capture_output=True, timeout=5).stdout.decode()
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return dict(l.split("=", 1) for l in out.strip().splitlines() if "=" in l)


def _issuer_org(names: dict) -> str:
    m = re.search(r"O\s*=\s*([^,]+)", names.get("issuer", ""))
    return m.group(1).strip().strip('"') if m else names.get("issuer", "")


def check_tls(rep: Report, update_baseline: bool) -> None:
    """Detect TLS interception: certs that don't verify, or issuers that differ from a trusted baseline."""
    baseline = load_json(BASELINE, {})
    results = {}
    for host in TLS_HOSTS:
        r = {"verified": False}
        try:
            with socket.create_connection((host, 443), timeout=6) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as s:
                    der = s.getpeercert(binary_form=True)
                    r["verified"] = True
        except ssl.SSLCertVerificationError as e:
            r["error"] = e.verify_message
            try:
                ctx = ssl._create_unverified_context()
                with socket.create_connection((host, 443), timeout=6) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as s:
                        der = s.getpeercert(binary_form=True)
            except OSError:
                der = b""
        except OSError as e:
            r["error"] = str(e)
            der = b""
        if der:
            names = _openssl_names(der)
            r.update(issuer=names.get("issuer", ""), issuer_org=_issuer_org(names),
                     sha256=hashlib.sha256(der).hexdigest())
        results[host] = r
    rep.data["tls"] = results

    failed = {h: r for h, r in results.items() if not r["verified"] and r.get("issuer")}
    if failed:
        rep.add("high", "TLS interception: certificates fail verification",
                "Something on this network is presenting its own certificates for major sites. "
                "Do NOT click through certificate warnings or log in to anything here.",
                hosts={h: {"issuer": r["issuer"], "error": r.get("error")} for h, r in failed.items()})
    unreachable = [h for h, r in results.items() if not r.get("issuer")]
    if unreachable:
        rep.note(f"TLS: couldn't connect to {', '.join(unreachable)}")

    if update_baseline:
        save_json(BASELINE, {h: r["issuer_org"] for h, r in results.items() if r["verified"]})
        rep.note(f"Saved TLS issuer baseline to {BASELINE}")
    elif baseline:
        changed = {h: {"baseline": baseline[h], "now": r.get("issuer_org")}
                   for h, r in results.items() if h in baseline and r.get("issuer_org") and r["issuer_org"] != baseline[h]}
        if changed:
            rep.add("medium", "Certificate issuers differ from your trusted baseline",
                    "Usually a CA change by the site; occasionally a sign of interception. Compare at home.", hosts=changed)
    else:
        rep.note("No TLS baseline yet: run `travelsec wifi --baseline` on a network you trust.")


def check_exposure(rep: Report, net) -> None:
    """What does *this laptop* expose to everyone else on the network?"""
    fw = firewall()
    rep.data["firewall"] = fw
    blocking = fw["name"] and fw["inbound_default"].upper() in ("DROP", "REJECT", "DENY")
    if not fw["name"]:
        rep.add("medium", "No host firewall detected",
                "Nothing stops other people on this network from reaching services on your laptop. "
                "Enable ufw (`sudo ufw enable`) before using public Wi-Fi.", scope="device")
    listeners = []
    for line in run(["ss", "-H", "-tuln"]).splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto, local = f[0], f[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if addr not in ("0.0.0.0", "*", "::") and addr != net.address:
            continue
        # UDP sockets on high ports are almost always outbound client sockets (browsers, VoIP), not servers
        if proto == "udp" and (port in ("5353", "68", "546") or (port.isdigit() and int(port) >= 32768)):
            continue
        listeners.append({"proto": proto, "addr": addr, "port": port})
    rep.data["my_listeners"] = listeners
    if listeners:
        rep.add("info" if blocking else "medium", "Your laptop has services listening on all interfaces",
                ("Your firewall's default-deny policy should block them, unless you added allow rules. "
                 if blocking else "Other people on this network can try to connect to these. ") +
                "Check with `ss -tulnp`.", scope="device", listeners=listeners)

    services = mdns_browse(timeout=8)
    others = sorted({s["ip"] for s in services if s["ip"] != net.address})
    rep.data["visible_peers"] = others
    if others:
        rep.add("low", f"No client isolation: {len(others)} other device(s) visible",
                "Devices on this network can see each other, so others can see and reach your laptop too. "
                "Common at home; a sign of a sloppy setup in a café or hotel.",
                examples=sorted({f"{s['name']} ({s['type']})" for s in services if s['ip'] != net.address})[:15])
    elif note := discovery_blocked_note(fw):
        rep.note("Client-isolation check inconclusive. " + note)


def check_public_ip(rep: Report) -> None:
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=6) as r:
            d = json.load(r)
        rep.data["public_ip"] = {k: d.get(k) for k in ("ip", "org", "city", "country")}
    except Exception:
        pass


def verdict(rep: Report) -> str:
    worst = rep.worst("network")
    return {
        "high": "AVOID or use a VPN for everything. This network is actively tampering with traffic.",
        "medium": "Use a VPN. The network is doing more than just passing traffic along.",
        "low": "Usable with HTTPS. Prefer a VPN for anything sensitive; shared-key Wi-Fi isn't private.",
        "info": "Looks clean. Normal precautions apply (HTTPS everywhere; the operator still sees domain names).",
    }[worst]


def run_wifi(label: str = "", baseline: bool = False) -> Report:
    rep = Report("wifi", label=label)
    net = net_info()
    rep.data["network"] = {k: v for k, v in vars(net).items()}
    if not net.gateway:
        rep.add("high", "No network connection", "Connect first, then re-run.")
        return rep
    check_link(rep, net)
    check_evil_twin(rep, net)
    portal = check_captive_portal(rep)
    if portal:
        rep.note("Captive portal detected; DNS/HTTP results may reflect the portal, not the real network.")
    check_http_tampering(rep)
    check_dns(rep, net)
    check_tls(rep, baseline)
    check_exposure(rep, net)
    check_public_ip(rep)
    rep.data["verdict"] = verdict(rep)
    return rep
