#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          WEBSITE INFORMATION SCANNER 🌍                      ║
║  Collects IP, Headers, Server Technology & More              ║
╚══════════════════════════════════════════════════════════════╝

Author  : Security & Recon Toolkit
Version : 1.0.0
Purpose : Educational website reconnaissance and information gathering
"""

import socket
import ssl
import json
import sys
import os
import re
import datetime
from urllib.parse import urlparse

# Dependencies are installed explicitly from requirements.txt; never modify
# the user's Python environment automatically at runtime.
import requests
import dns.resolver
import dns.reversename
import colorama
from colorama import Fore, Back, Style
from tabulate import tabulate
import whois

colorama.init(autoreset=True)

# ─────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────
def print_banner():
    banner = f"""
{Fore.CYAN}{'═'*65}
{Fore.CYAN}  🌍  WEBSITE INFORMATION SCANNER
{Fore.CYAN}  Recon Tool — IP · Headers · DNS · WHOIS · SSL · Tech Stack
{Fore.CYAN}{'═'*65}{Style.RESET_ALL}
"""
    print(banner)


# ─────────────────────────────────────────────────────────────
# UTILITY HELPERS
# ─────────────────────────────────────────────────────────────
def normalize_url(target: str) -> str:
    """Normalize an HTTP(S) URL and reject ambiguous or credential-bearing input."""
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    value = target.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must include a hostname and must not contain credentials.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("URL contains invalid control characters.")
    return value.rstrip("/")


def extract_hostname(url: str) -> str:
    return urlparse(url).hostname or url


def section(title: str):
    print(f"\n{Fore.YELLOW}{'─'*55}")
    print(f"{Fore.YELLOW}  {title}")
    print(f"{Fore.YELLOW}{'─'*55}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────
# 1. IP ADDRESS LOOKUP
# ─────────────────────────────────────────────────────────────
def get_ip_info(hostname: str) -> dict:
    """
    DEFINITION:
        IP Address Lookup resolves the domain name to its underlying
        IPv4/IPv6 address(es) using the DNS system.  Every website
        lives on a server identified by an IP address; the domain
        name is just a human-readable alias.

    LEARNING:
        - socket.getaddrinfo() queries the OS resolver (uses /etc/hosts
          then DNS).
        - Returns a list of (family, type, proto, canonname, sockaddr).
        - AF_INET  → IPv4 (e.g. 93.184.216.34)
        - AF_INET6 → IPv6 (e.g. 2606:2800:220:1:248:1893:25c8:1946)
    """
    result = {"ipv4": [], "ipv6": [], "hostname": hostname}
    try:
        info = socket.getaddrinfo(hostname, None)
        for item in info:
            addr = item[4][0]
            if item[0] == socket.AF_INET and addr not in result["ipv4"]:
                result["ipv4"].append(addr)
            elif item[0] == socket.AF_INET6 and addr not in result["ipv6"]:
                result["ipv6"].append(addr)
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# 2. HTTP HEADERS
# ─────────────────────────────────────────────────────────────
def get_http_headers(url: str) -> dict:
    """
    DEFINITION:
        HTTP Headers are key-value pairs sent by the server at the
        start of every response.  They carry metadata: content type,
        encoding, caching rules, security policies, and server identity.

    LEARNING:
        - requests.head() fetches ONLY headers (no body) — fast.
        - requests.get()  fetches headers + body.
        - Security headers like X-Frame-Options, Content-Security-Policy,
          Strict-Transport-Security protect users from common attacks.
        - The Server header often reveals web server software (Apache,
          Nginx, IIS, etc.) and sometimes its version.
        - X-Powered-By may leak the backend language/framework (PHP, ASP).
    """
    result = {"headers": {}, "status_code": None, "redirect_chain": []}
    try:
        resp = requests.get(url, timeout=(3, 10), allow_redirects=False,
                            headers={"User-Agent": "WebScanner/1.0"})
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)

        # Capture redirect chain
        for r in resp.history:
            result["redirect_chain"].append({
                "url": r.url,
                "status": r.status_code
            })
        result["final_url"] = resp.url
    except requests.RequestException as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# 3. SERVER TECHNOLOGY DETECTION
# ─────────────────────────────────────────────────────────────
TECH_SIGNATURES = {
    # Web Servers
    "Apache":       {"headers": ["Server"], "pattern": r"Apache"},
    "Nginx":        {"headers": ["Server"], "pattern": r"[Nn]ginx"},
    "IIS":          {"headers": ["Server"], "pattern": r"Microsoft-IIS"},
    "LiteSpeed":    {"headers": ["Server"], "pattern": r"LiteSpeed"},
    "Caddy":        {"headers": ["Server"], "pattern": r"Caddy"},
    "Cloudflare":   {"headers": ["Server", "CF-RAY"], "pattern": r"cloudflare"},
    # Languages / Frameworks
    "PHP":          {"headers": ["X-Powered-By"], "pattern": r"PHP"},
    "ASP.NET":      {"headers": ["X-Powered-By", "X-AspNet-Version"], "pattern": r"ASP\.NET"},
    "Express.js":   {"headers": ["X-Powered-By"], "pattern": r"Express"},
    "Django":       {"headers": ["X-Frame-Options"], "pattern": r"SAMEORIGIN"},
    # CDN / Proxies
    "Varnish":      {"headers": ["X-Varnish", "Via"], "pattern": r"[Vv]arnish"},
    "Fastly":       {"headers": ["X-Served-By"], "pattern": r"fastly"},
    "Akamai":       {"headers": ["X-Check-Cacheable"], "pattern": r""},
    # Security
    "HSTS":         {"headers": ["Strict-Transport-Security"], "pattern": r"max-age"},
    "CSP":          {"headers": ["Content-Security-Policy"], "pattern": r""},
}

def detect_technologies(headers: dict) -> list:
    """
    DEFINITION:
        Technology Detection (Fingerprinting) identifies what software
        stack powers a website by inspecting characteristic HTTP response
        headers.  This is a passive recon technique — no probing needed.

    LEARNING:
        - Each web server, language runtime, and CDN leaves unique
          'fingerprints' in specific headers.
        - Attackers use this to find known CVEs for detected versions.
        - Defenders use it to audit what they accidentally expose.
        - Tools like Wappalyzer, WhatWeb, and BuiltWith automate this.
    """
    detected = []
    header_lower = {k.lower(): v for k, v in headers.items()}

    for tech, sig in TECH_SIGNATURES.items():
        for hdr in sig["headers"]:
            value = header_lower.get(hdr.lower(), "")
            pattern = sig["pattern"]
            if value and (not pattern or re.search(pattern, value, re.IGNORECASE)):
                version = ""
                if pattern:
                    m = re.search(r"[\d.]+", value)
                    version = m.group(0) if m else ""
                detected.append({"technology": tech, "header": hdr,
                                  "value": value[:60], "version": version})
                break
    return detected


# ─────────────────────────────────────────────────────────────
# 4. DNS RECORDS
# ─────────────────────────────────────────────────────────────
def get_dns_records(hostname: str) -> dict:
    """
    DEFINITION:
        DNS (Domain Name System) Records are entries in the global
        distributed database that maps names to resources.  Different
        record types serve different purposes.

    LEARNING:
        Record Types:
        - A     : Maps domain → IPv4 address
        - AAAA  : Maps domain → IPv6 address
        - MX    : Mail exchange servers (who handles email)
        - NS    : Authoritative name servers for the domain
        - TXT   : Arbitrary text — used for SPF, DKIM, domain verification
        - CNAME : Alias from one name to another
        - SOA   : Start of Authority — admin info about the zone

        DNS enumeration reveals hosting providers, mail providers,
        CDN usage, and can uncover subdomains.
    """
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


# ─────────────────────────────────────────────────────────────
# 5. SSL / TLS CERTIFICATE INFO
# ─────────────────────────────────────────────────────────────
def get_ssl_info(hostname: str) -> dict:
    """
    DEFINITION:
        SSL/TLS Certificates establish encrypted connections (HTTPS)
        and authenticate the server's identity.  The certificate is
        issued by a Certificate Authority (CA) and contains the owner's
        name, validity period, and public key.

    LEARNING:
        - ssl.create_default_context() builds a secure SSL context.
        - getpeercert() retrieves the DER-encoded certificate data.
        - Key fields: subject, issuer, notBefore, notAfter, SANs.
        - Subject Alternative Names (SANs) list all hostnames the cert covers.
        - Expired or self-signed certs trigger browser security warnings.
        - TLS 1.0/1.1 are deprecated; TLS 1.2+ is required; TLS 1.3 preferred.
    """
    result = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            result["tls_version"] = s.version()
            result["cipher"]      = s.cipher()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        result["subject"]    = subject
        result["issuer"]     = issuer
        result["valid_from"] = cert.get("notBefore")
        result["valid_until"]= cert.get("notAfter")
        result["serial"]     = cert.get("serialNumber")

        sans = []
        for item in cert.get("subjectAltName", []):
            if item[0] == "DNS":
                sans.append(item[1])
        result["san"] = sans

        # Check expiry
        exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (exp - datetime.datetime.utcnow()).days
        result["days_until_expiry"] = days_left
        result["expired"] = days_left < 0

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# 6. WHOIS LOOKUP
# ─────────────────────────────────────────────────────────────
def get_whois_info(hostname: str) -> dict:
    """
    DEFINITION:
        WHOIS is a query protocol that retrieves registration information
        about a domain name from the registrar's database.

    LEARNING:
        - WHOIS records show: registrar, creation/expiry dates,
          name servers, and sometimes registrant contact info.
        - GDPR (since 2018) has caused many registrars to redact
          personal contact info (privacy protection).
        - Useful for: finding abuse contacts, understanding domain age,
          identifying hosting provider changes.
        - Tools: `whois` CLI, python-whois library, who.is website.
    """
    try:
        w = whois.whois(hostname)
        return {
            "registrar":       str(w.registrar or "N/A"),
            "creation_date":   str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "updated_date":    str(w.updated_date or "N/A"),
            "name_servers":    list(w.name_servers or []),
            "status":          str(w.status or "N/A"),
            "emails":          str(w.emails or "N/A"),
            "country":         str(w.country or "N/A"),
            "org":             str(w.org or "N/A"),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────
# 7. SECURITY HEADERS AUDIT
# ─────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "Content-Security-Policy":   "Prevents XSS & injection",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Referrer-Policy":           "Controls referrer leakage",
    "Permissions-Policy":        "Restricts browser features",
    "X-XSS-Protection":          "Legacy XSS filter (deprecated)",
}

def audit_security_headers(headers: dict) -> list:
    """
    DEFINITION:
        Security Header Audit checks whether the server sends the
        recommended HTTP response headers that protect users from
        common web attacks.

    LEARNING:
        - Missing HSTS → users can be downgraded to HTTP (MITM risk).
        - Missing CSP  → site is vulnerable to cross-site scripting.
        - Missing X-Frame-Options → clickjacking attacks possible.
        - Tools like securityheaders.com grade sites on header presence.
        - OWASP provides a full Security Headers cheat sheet.
    """
    header_lower = {k.lower(): v for k, v in headers.items()}
    audit = []
    for hdr, desc in SECURITY_HEADERS.items():
        present = hdr.lower() in header_lower
        audit.append({
            "header":  hdr,
            "present": "✅ YES" if present else "❌ MISSING",
            "purpose": desc,
            "value":   (header_lower.get(hdr.lower(), "")[:50]) if present else "—"
        })
    return audit


# ─────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────
def display_ip(data):
    section("1. IP ADDRESS RESOLUTION")
    rows = []
    for ip in data.get("ipv4", []):
        rows.append(["IPv4", ip])
    for ip in data.get("ipv6", []):
        rows.append(["IPv6", ip])
    if not rows:
        print(f"{Fore.RED}  No IP addresses found.")
    else:
        print(tabulate(rows, headers=["Type", "Address"],
                       tablefmt="rounded_outline"))


def display_headers(data):
    section("2. HTTP RESPONSE HEADERS")
    if "error" in data:
        print(f"{Fore.RED}  Error: {data['error']}")
        return
    print(f"  Status Code : {Fore.GREEN}{data.get('status_code')}")
    print(f"  Final URL   : {data.get('final_url', 'N/A')}")
    if data.get("redirect_chain"):
        print(f"\n  {Fore.CYAN}Redirect Chain:")
        for r in data["redirect_chain"]:
            print(f"    {r['status']} → {r['url']}")
    print()
    rows = [[k, v[:70]] for k, v in data.get("headers", {}).items()]
    print(tabulate(rows, headers=["Header", "Value"],
                   tablefmt="rounded_outline", maxcolwidths=[30, 70]))


def display_tech(techs):
    section("3. SERVER TECHNOLOGY FINGERPRINT")
    if not techs:
        print(f"  {Fore.YELLOW}No technologies detected from headers.")
        return
    rows = [[t["technology"], t["version"] or "—", t["header"], t["value"]]
            for t in techs]
    print(tabulate(rows, headers=["Technology", "Version", "Via Header", "Header Value"],
                   tablefmt="rounded_outline"))


def display_dns(records):
    section("4. DNS RECORDS")
    rows = []
    for rtype, values in records.items():
        for v in values:
            rows.append([rtype, v[:80]])
    if not rows:
        print(f"{Fore.RED}  No DNS records found.")
    else:
        print(tabulate(rows, headers=["Type", "Value"],
                       tablefmt="rounded_outline"))


def display_ssl(data):
    section("5. SSL / TLS CERTIFICATE")
    if "error" in data:
        print(f"  {Fore.RED}Error: {data['error']}")
        return
    subj = data.get("subject", {})
    issuer = data.get("issuer", {})
    days = data.get("days_until_expiry", 0)
    color = Fore.GREEN if days > 30 else (Fore.YELLOW if days > 0 else Fore.RED)
    rows = [
        ["TLS Version",     data.get("tls_version", "N/A")],
        ["Cipher Suite",    str(data.get("cipher", "N/A"))],
        ["Common Name",     subj.get("commonName", "N/A")],
        ["Organization",    subj.get("organizationName", "N/A")],
        ["Issued By",       issuer.get("organizationName", "N/A")],
        ["Valid From",      data.get("valid_from", "N/A")],
        ["Valid Until",     data.get("valid_until", "N/A")],
        ["Days Remaining",  f"{color}{days}{Style.RESET_ALL}"],
        ["Expired",         "YES ⚠️" if data.get("expired") else "No ✅"],
        ["Serial Number",   data.get("serial", "N/A")],
    ]
    print(tabulate(rows, headers=["Field", "Value"],
                   tablefmt="rounded_outline"))
    if data.get("san"):
        print(f"\n  {Fore.CYAN}Subject Alternative Names (SANs):")
        for san in data["san"][:10]:
            print(f"    • {san}")
        if len(data["san"]) > 10:
            print(f"    ... and {len(data['san'])-10} more")


def display_whois(data):
    section("6. WHOIS REGISTRATION INFO")
    if "error" in data:
        print(f"  {Fore.YELLOW}WHOIS lookup failed: {data['error']}")
        return
    rows = [[k.replace("_", " ").title(), str(v)[:80]]
            for k, v in data.items() if k != "name_servers"]
    print(tabulate(rows, headers=["Field", "Value"],
                   tablefmt="rounded_outline"))
    if data.get("name_servers"):
        print(f"\n  {Fore.CYAN}Name Servers:")
        for ns in data["name_servers"][:6]:
            print(f"    • {ns}")


def display_security_audit(audit):
    section("7. SECURITY HEADERS AUDIT")
    rows = [[a["header"], a["present"], a["purpose"]] for a in audit]
    print(tabulate(rows,
                   headers=["Security Header", "Status", "Purpose"],
                   tablefmt="rounded_outline"))


# ─────────────────────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────────────────────
def save_report(target: str, all_data: dict):
    safe_name = re.sub(r"[^\w\-]", "_", target)
    filename  = f"scan_{safe_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(all_data, f, indent=2, default=str)
    print(f"\n{Fore.GREEN}  ✅  Report saved → {filename}{Style.RESET_ALL}")
    return filename


# ─────────────────────────────────────────────────────────────
# MAIN FLOW
# ─────────────────────────────────────────────────────────────
def scan(target: str, save: bool = False):
    """
    FULL SCAN FLOW:
    ──────────────────────────────────────────────────────
    INPUT   : target URL or domain
                e.g. "example.com" or "https://example.com"

    STEP 1  : Normalize URL → ensure https:// prefix
    STEP 2  : Extract hostname from URL
    STEP 3  : IP Resolution    → socket.getaddrinfo()
    STEP 4  : HTTP Headers     → requests.get()
    STEP 5  : Tech Detection   → regex on response headers
    STEP 6  : DNS Records      → dns.resolver (A,MX,NS,TXT…)
    STEP 7  : SSL Certificate  → ssl module + getpeercert()
    STEP 8  : WHOIS Lookup     → python-whois library
    STEP 9  : Security Audit   → check for security headers
    STEP 10 : (Optional) Save JSON report

    OUTPUT  : Colour-formatted terminal table + optional JSON file
    ──────────────────────────────────────────────────────
    """
    print_banner()
    url      = normalize_url(target)
    hostname = extract_hostname(url)

    print(f"  {Fore.CYAN}Target   : {Fore.WHITE}{url}")
    print(f"  {Fore.CYAN}Hostname : {Fore.WHITE}{hostname}")
    print(f"  {Fore.CYAN}Started  : {Fore.WHITE}{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Run all modules ──────────────────────────────────
    print(f"\n{Fore.CYAN}[*] Resolving IP address...")
    ip_data   = get_ip_info(hostname)

    print(f"{Fore.CYAN}[*] Fetching HTTP headers...")
    http_data = get_http_headers(url)

    print(f"{Fore.CYAN}[*] Detecting technologies...")
    techs     = detect_technologies(http_data.get("headers", {}))

    print(f"{Fore.CYAN}[*] Querying DNS records...")
    dns_data  = get_dns_records(hostname)

    print(f"{Fore.CYAN}[*] Checking SSL certificate...")
    ssl_data  = get_ssl_info(hostname)

    print(f"{Fore.CYAN}[*] Running WHOIS lookup...")
    whois_data = get_whois_info(hostname)

    print(f"{Fore.CYAN}[*] Auditing security headers...")
    sec_audit = audit_security_headers(http_data.get("headers", {}))

    # ── Display Results ──────────────────────────────────
    display_ip(ip_data)
    display_headers(http_data)
    display_tech(techs)
    display_dns(dns_data)
    display_ssl(ssl_data)
    display_whois(whois_data)
    display_security_audit(sec_audit)

    # ── Summary ──────────────────────────────────────────
    section("SCAN SUMMARY")
    missing = sum(1 for a in sec_audit if "MISSING" in a["present"])
    grade   = "A" if missing == 0 else "B" if missing <= 2 else "C" if missing <= 4 else "D"
    print(f"  IPv4 Addresses   : {len(ip_data.get('ipv4', []))}")
    print(f"  Technologies     : {len(techs)}")
    print(f"  DNS Record Types : {sum(1 for v in dns_data.values() if v)}")
    print(f"  SSL Days Left    : {ssl_data.get('days_until_expiry', 'N/A')}")
    print(f"  Security Grade   : {Fore.GREEN if grade=='A' else Fore.YELLOW}{grade}{Style.RESET_ALL} ({missing}/{len(sec_audit)} headers missing)")

    # ── Save Report ───────────────────────────────────────
    all_data = {
        "target": target, "hostname": hostname,
        "scanned_at": str(datetime.datetime.now()),
        "ip": ip_data, "http": http_data,
        "technologies": techs, "dns": dns_data,
        "ssl": ssl_data, "whois": whois_data,
        "security_audit": sec_audit,
    }
    if save:
        save_report(hostname, all_data)

    print(f"\n{Fore.CYAN}{'═'*65}{Style.RESET_ALL}\n")
    return all_data


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python website_scanner.py <domain> [--save]")
        print(f"       python website_scanner.py example.com")
        print(f"       python website_scanner.py https://example.com --save")
        sys.exit(1)

    target_url = sys.argv[1]
    save_flag  = "--save" in sys.argv

    try:
        scan(target_url, save=save_flag)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
