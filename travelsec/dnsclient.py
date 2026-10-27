"""Tiny stdlib DNS client: enough to ask a specific server a question and read the answer.

Used to tell whether the local network rewrites or intercepts DNS, which the
system resolver hides.
"""

from __future__ import annotations

import json
import random
import socket
import struct
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

TYPES = {"A": 1, "TXT": 16, "AAAA": 28}
CLASS_IN, CLASS_CH = 1, 3
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class Answer:
    rcode: str
    records: list[tuple[str, str]] = field(default_factory=list)  # (type, value)

    def values(self, rtype: str) -> list[str]:
        return [v for t, v in self.records if t == rtype]


def build_query(name: str, qtype: str = "A", qclass: int = CLASS_IN, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"
    return header + qname + struct.pack(">HH", TYPES[qtype], qclass)


def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(128):  # loop guard against malicious pointers
        n = msg[off]
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        if n == 0:
            return ".".join(labels), (end if jumped else off + 1)
        labels.append(msg[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    raise ValueError("name too long / pointer loop")


def parse_response(msg: bytes) -> Answer:
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    ans = Answer(RCODES.get(flags & 0xF, str(flags & 0xF)))
    rev = {v: k for k, v in TYPES.items()}
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        t = rev.get(rtype)
        if t == "A" and rdlen == 4:
            ans.records.append(("A", socket.inet_ntop(socket.AF_INET, rdata)))
        elif t == "AAAA" and rdlen == 16:
            ans.records.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
        elif t == "TXT":
            i, parts = 0, []
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1:i + 1 + ln].decode(errors="replace"))
                i += 1 + ln
            ans.records.append(("TXT", "".join(parts)))
    return ans


def query(server: str, name: str, qtype: str = "A", qclass: int = CLASS_IN, timeout: float = 3) -> Answer | None:
    """Ask `server` directly over UDP. Returns None on timeout (no reply at all)."""
    q = build_query(name, qtype, qclass)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(q, (server, 53))
            while True:
                data, _ = s.recvfrom(4096)
                if data[:2] == q[:2]:
                    return parse_response(data)
        except (socket.timeout, OSError):
            return None


def doh(name: str, qtype: str = "A", timeout: float = 5) -> Answer | None:
    """DNS-over-HTTPS via Cloudflare's JSON API; the answer the local network can't rewrite."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": qtype})
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
    except Exception:
        return None
    rev = {v: k for k, v in TYPES.items()}
    ans = Answer(RCODES.get(d.get("Status", -1), str(d.get("Status"))))
    for a in d.get("Answer", []):
        t = rev.get(a.get("type"))
        if t:
            ans.records.append((t, a["data"].strip('"')))
    return ans


def random_nonexistent() -> str:
    """A .com name that almost certainly isn't registered."""
    return "travelsec-" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20)) + ".com"
