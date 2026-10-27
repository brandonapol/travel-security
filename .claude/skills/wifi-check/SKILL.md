---
name: wifi-check
description: Check whether the Wi-Fi network I'm on (café, hotel, airport, Airbnb) is spying on or tampering with my traffic — captive portals, DNS hijacking/interception, TLS interception, injected content, evil-twin hotspots, missing client isolation — and give a plain-language verdict on whether to use it. Use when the user says they just joined a network, asks "is this wifi safe", "is this network spying on me", or wants a TLS baseline recorded at home.
---

# Wi-Fi self-check

Runs `travelsec wifi`, which only inspects **the user's own connection**: requests they make, answers they get back, and what their laptop exposes. It never probes other clients or the operator's equipment, so it's fine on any network the user is legitimately on.

## Steps

1. If the user hasn't recorded a TLS baseline (the report notes "No TLS baseline yet") and says they're on a trusted network (home), run with `--baseline` first.
2. Run from the repo root, labeling the place if the user named it:
   ```bash
   python3 -m travelsec --json wifi --label "<place>"
   ```
   It takes about 15–30 s. If a captive portal is detected, ask the user to finish the portal login, then re-run.
3. Read the JSON (stdout; also saved under `~/.local/share/travelsec/reports/`).

## How to interpret

Lead with the verdict (`data.verdict`) in one sentence, then the findings that matter, in plain language. Separate **network** findings (scope `network`) from **your laptop** findings (scope `device`).

- **TLS interception (high):** the most serious result. Tell them not to log in to anything and not to click through certificate warnings; leave or use a VPN that pins its server certificate. Show the issuer that was presented.
- **DNS transparently intercepted / 1.1.1.1 rewritten (high/medium):** the operator sees and can alter every lookup, even if the user configured another resolver. DoH (browser setting) or a VPN fixes it.
- **NXDOMAIN hijacking (medium):** typo domains get redirected to ad pages. Mostly an ISP or hotel monetization sign that they're willing to rewrite traffic.
- **HTTP page modified / headers injected (medium–high):** active injection. Show the injected tags or headers.
- **Evil twin (high):** same SSID, different security. Tell them to confirm the real network with staff.
- **Open / WEP / WPA2-shared-password:** explain who can read what. With HTTPS, page contents are still protected; domain names (SNI/DNS) and metadata aren't.
- **No client isolation (low):** others can reach the laptop. Check `data.firewall`; if a default-deny firewall is active, the risk is small.
- **Device findings:** listening services or no firewall. Give the exact fix (`sudo ufw enable`, or stop the service shown by `ss -tulnp`).
- `data.public_ip.org` shows who actually carries the traffic; mention it when it's surprising (e.g. a VPN or proxy company rather than an ISP).

Close with 2–4 concrete actions ranked by importance. Don't pad a clean result with alarm: if the verdict is clean, say so.

## Limits to mention when relevant

- An operator can still log the domain names and timing of your traffic on any network without a VPN; no test can rule that out.
- TLS checks cover a handful of major sites. Interception targeted at one site can slip past.
- If the report notes that discovery is blocked by the firewall, the client-isolation result is inconclusive, and that's fine. Don't suggest opening the firewall on public Wi-Fi just for this check.
