#!/usr/bin/env python3
"""
Skill: cf1016_check
====================
Tests a domain (or a single subdomain) for the Cloudflare 1016 dangling DNS
vulnerability.

What is CF-1016?
  A Cloudflare "Error 1016 – Origin DNS Error" response means:
    • The DNS record still routes traffic through Cloudflare's proxy.
    • The backend origin has been deleted / deactivated.
    • An attacker who can claim the abandoned origin can hijack the subdomain.

Detection strategy (body-first, strict match):
  1. HTTP GET the subdomain — do NOT follow redirects.
  2. Check for the EXACT CF-1016 error strings in the response body:
       "error code: 1016"              (plain-text, as seen in curl output)
       "error 1016" + "origin dns error"  (HTML page heading + subtitle)
  3. Confirm the resolved IPs are all in Cloudflare's published CIDR ranges.

Why body-first?
  • Avoids false positives: matrix.paysera.com resolves to Cloudflare IPs
    but returns a legitimate redirect — its body does NOT contain the CF-1016
    marker strings, so it is correctly skipped.
  • Avoids false negatives: a host can return 1016 even if DNS briefly
    flips off Cloudflare CIDRs.

Usage (Open Interpreter / Qwen paw):
  python3 skill_cf1016_check.py <domain-or-subdomain> [--threads N] [--timeout S]

Examples:
  python3 skill_cf1016_check.py example.com
  python3 skill_cf1016_check.py test.entrust.com          # single host
  python3 skill_cf1016_check.py example.com --threads 50 --timeout 8
  python3 skill_cf1016_check.py example.com --subs-file /tmp/subs.txt

Output:
  Human-readable summary, or --json for machine-readable output.
  Exit code: 0 = no findings, 1 = vulnerabilities found.

Dependencies (stdlib only – no pip installs needed):
  socket, ipaddress, urllib.request, concurrent.futures, json, re, sys, argparse
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Cloudflare CIDR ranges (IPv4 + IPv6) ──────────────────────────────────
# Source: https://www.cloudflare.com/ips-v4  /  /ips-v6
_CF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]
CF_NETS = [ipaddress.ip_network(c) for c in _CF_CIDRS]


# ─── Helpers ────────────────────────────────────────────────────────────────

def is_cloudflare_ip(ip_str: str) -> bool:
    """Return True if ip_str falls inside any Cloudflare CIDR."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETS)


def resolve(hostname: str) -> list[str]:
    """Return the list of IP addresses for *hostname*, or [] on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


# ─── Core detection ─────────────────────────────────────────────────────────

# Custom opener that does NOT follow redirects.
# A CF-1016 error page is always served at the first response — it is never
# behind a redirect. Stopping here prevents hitting legitimate pages that
# happen to sit behind CF load-balancers (e.g. matrix.paysera.com redirects
# to /_matrix/static which is a valid page, not an error).
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # abort all redirects


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def check_subdomain(subdomain: str, timeout: float) -> dict | None:
    """
    Return a finding dict if *subdomain* shows the CF-1016 error page.
    Returns None if the host is clean or unreachable.

    Strategy: body-first → IP confirm.
    """
    # Normalise hostname
    hostname = (
        subdomain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .strip()
    )
    if not hostname:
        return None

    # ── Step 1: HTTP probe — body is the ground truth ───────────────────────
    body = ""
    status_code = -1

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CF1016-Checker/1.0)"},
        )
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
                body = resp.read(8192).decode("utf-8", errors="replace")
                status_code = resp.status
                break
        except urllib.error.HTTPError as e:
            # HTTP error responses (4xx/5xx) still have a readable body.
            try:
                body = e.read(8192).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            status_code = e.code
            break  # got a response — don't try http fallback
        except Exception:
            continue  # connection failed — try next scheme

    if status_code == -1:
        return None  # both schemes failed (host is down / DNS NXDOMAIN)

    # ── Step 2: Strict body check — exact CF-1016 wording required ──────────
    # Cloudflare's error page always contains one of these patterns:
    #
    #   "error code: 1016"                 ← plain-text (curl output)
    #   "Error 1016" + "Origin DNS error"  ← HTML heading + subtitle
    #
    # We do NOT match on the bare string "1016" — that would match version
    # numbers, port numbers, timestamps, etc. and cause false positives.
    body_lower = body.lower()
    is_cf1016 = (
        "error code: 1016" in body_lower
        or (
            "error 1016" in body_lower
            and "origin dns error" in body_lower
        )
    )

    if not is_cf1016:
        return None  # body does not match — clean host (e.g. matrix.paysera.com)

    # ── Step 3: Confirm Cloudflare IPs (secondary sanity check) ────────────
    # If the body matched but the IPs are NOT Cloudflare-owned, something
    # very unusual is happening — skip to avoid a bizarre false positive.
    ips = resolve(hostname)
    if ips and not all(is_cloudflare_ip(ip) for ip in ips):
        return None

    return {
        "subdomain": hostname,
        "ips": ips or ["(dns-lookup-failed)"],
        "http_status": status_code,
        "type": "DNS Misconfiguration / Dangling Record (CF-1016)",
        "severity": "HIGH",
        "description": (
            f"{hostname} resolves to Cloudflare IPs "
            f"({', '.join(ips or ['unknown'])}) but returns HTTP {status_code} "
            "with Cloudflare error 1016 (Origin DNS Error). "
            "The backend origin has been removed while the DNS record still "
            "routes through Cloudflare — an attacker who claims the origin "
            "can hijack this subdomain."
        ),
    }


# ─── Subdomain enumeration (passive, stdlib only) ───────────────────────────

def _fetch(url: str, timeout: float = 15) -> str:
    """Fetch *url* and return body text, or '' on error."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; CF1016-Checker/1.0)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return ""


def enumerate_subdomains(domain: str) -> list[str]:
    """
    Collect subdomains from passive DNS sources.
    Returns a sorted, deduplicated list of subdomain strings.
    No API keys required for any source.
    """
    pattern = re.compile(
        r"(?:[a-zA-Z0-9_-]+\.)*" + re.escape(domain),
        re.IGNORECASE,
    )
    found: set[str] = set()

    def add(text: str):
        for m in pattern.findall(text):
            sub = m.strip().lower().lstrip("*.")
            if sub and sub != domain:
                found.add(sub)

    print(f"[*] Enumerating subdomains for {domain} via passive sources…")

    # crt.sh — Certificate Transparency
    crt = _fetch(f"https://crt.sh/?q=%.{domain}&output=json")
    try:
        for entry in json.loads(crt):
            add(entry.get("name_value", ""))
    except Exception:
        add(crt)

    # HackerTarget — plain-text CSV
    add(_fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}"))

    # AlienVault OTX — passive DNS
    otx = _fetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    try:
        for rec in json.loads(otx).get("passive_dns", []):
            add(rec.get("hostname", ""))
    except Exception:
        add(otx)

    # RapidDNS — HTML scrape
    add(_fetch(f"https://rapiddns.io/subdomain/{domain}?full=1"))

    # urlscan.io
    us = _fetch(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200")
    try:
        for result in json.loads(us).get("results", []):
            add(result.get("page", {}).get("domain", ""))
    except Exception:
        pass

    subs = sorted(found)
    print(f"[*] Found {len(subs)} unique subdomains")
    return subs


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Check a domain/subdomain for Cloudflare CF-1016 dangling DNS records.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="Root domain (e.g. example.com) or single subdomain (e.g. test.entrust.com)",
    )
    parser.add_argument("--threads", type=int, default=100, metavar="N",
                        help="Concurrent workers (default: 100)")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="S",
                        help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--subs-file", metavar="FILE",
                        help="File with one subdomain per line (skips enumeration)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array")
    args = parser.parse_args()

    target = args.target.strip()
    parts = target.replace("https://", "").replace("http://", "").split("/")[0].split(".")

    # ── Build the list of subdomains to probe ─────────────────────────────
    if args.subs_file:
        with open(args.subs_file) as fh:
            to_scan = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        print(f"[*] Loaded {len(to_scan)} subdomains from {args.subs_file}")
    elif len(parts) > 2:
        # Looks like a subdomain — probe only that one host
        to_scan = [target]
        print(f"[*] Single-host mode: probing {target}")
    else:
        # Root domain — enumerate first
        to_scan = enumerate_subdomains(target)
        if not to_scan:
            print(f"[!] No subdomains found for {target}. Nothing to scan.")
            sys.exit(0)

    print(
        f"[*] Scanning {len(to_scan)} subdomain(s) for CF-1016 "
        f"(threads={args.threads}, timeout={args.timeout}s)…"
    )
    t0 = time.time()

    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_subdomain, sub, args.timeout): sub for sub in to_scan}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)
                print(
                    f"  [VULN] {result['subdomain']} "
                    f"→ HTTP {result['http_status']} — CF Error 1016 detected!"
                )

    elapsed = time.time() - t0
    print(f"\n[*] Scan complete in {elapsed:.1f}s — {len(findings)} finding(s)\n")

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if findings:
            print("=" * 70)
            print(f"  VULNERABLE SUBDOMAINS ({len(findings)} found)")
            print("=" * 70)
            for f in findings:
                print(f"  Subdomain  : {f['subdomain']}")
                print(f"  IPs        : {', '.join(f['ips'])}")
                print(f"  HTTP Status: {f['http_status']}")
                print(f"  Severity   : {f['severity']}")
                print(f"  Description: {f['description']}")
                print()
        else:
            print("  No CF-1016 dangling DNS records found.")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
