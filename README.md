# 🌍 Website Information Scanner

> **Tool #9** — Security & Recon Toolkit  
> *Collects information about a website including IP address, server type, HTTP headers, DNS records, SSL certificates, WHOIS data, and security header audits.*

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Full Program Flow](#full-program-flow)
6. [Module Definitions & Learning](#module-definitions--learning)
   - [IP Address Resolution](#1-ip-address-resolution)
   - [HTTP Headers](#2-http-headers)
   - [Server Technology Detection](#3-server-technology-detection)
   - [DNS Records](#4-dns-records)
   - [SSL/TLS Certificate](#5-ssltls-certificate)
   - [WHOIS Lookup](#6-whois-lookup)
   - [Security Headers Audit](#7-security-headers-audit)
7. [Output & Report](#output--report)
8. [Sample Output](#sample-output)
9. [Educational Definitions Glossary](#educational-definitions-glossary)
10. [Ethics & Legal Notice](#ethics--legal-notice)

---

## Overview

The **Website Information Scanner** is a passive reconnaissance tool that gathers comprehensive publicly available information about any website or domain. It performs **no intrusive probing** — it only uses standard DNS queries, HTTP requests, SSL handshakes, and WHOIS lookups, all of which any browser does automatically when you visit a site.

**Use cases:**
- Security audits of your own infrastructure
- Learning web technologies and protocols
- Verifying your server configuration
- Competitive technical research
- Penetration testing preparation (authorized engagements only)

---

## Features

| Module | What It Collects |
|--------|-----------------|
| 🔍 IP Resolution | IPv4 & IPv6 addresses |
| 📨 HTTP Headers | All response headers, status code, redirects |
| 🖥️ Tech Fingerprint | Web server, language, CDN, framework detection |
| 🌐 DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA |
| 🔒 SSL/TLS | Certificate issuer, validity, SANs, cipher, TLS version |
| 📋 WHOIS | Registrar, creation/expiry dates, name servers |
| 🛡️ Security Audit | Checks for 7 critical security response headers |
| 📊 Report | Saves JSON scan report with all findings |

---

## Installation

### Requirements
- Python 3.7+
- Internet connection

### Steps

```bash
# Clone or download the project
git clone https://github.com/yourusername/website-scanner
cd website_scanner

# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests dnspython colorama tabulate python-whois
```

> **Note:** The script auto-installs missing packages on first run.

---

## Usage

```bash
# Basic scan
python website_scanner.py example.com

# Scan with https:// prefix (optional)
python website_scanner.py https://example.com

# Scan and save JSON report
python website_scanner.py example.com --save

# Scan any domain
python website_scanner.py google.com --save
python website_scanner.py github.com
python website_scanner.py yourwebsite.com --save
```

---

## Full Program Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   WEBSITE INFORMATION SCANNER                   │
│                         Program Flow                            │
└─────────────────────────────────────────────────────────────────┘

INPUT: User provides domain / URL
          │
          ▼
┌─────────────────────┐
│  1. Normalize URL   │  Ensure https:// prefix, strip trailing /
│  2. Extract Hostname│  Parse hostname from full URL
└────────┬────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────────┐
│              PARALLEL INFORMATION GATHERING                    │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   IP Module  │  │  HTTP Module │  │    DNS Module        │ │
│  │              │  │              │  │                      │ │
│  │socket.get    │  │requests.get()│  │dns.resolver.resolve()│ │
│  │addrinfo()    │  │→ headers,    │  │→ A, AAAA, MX, NS,   │ │
│  │→ IPv4, IPv6  │  │  status,     │  │  TXT, CNAME, SOA    │ │
│  │              │  │  redirects   │  │                      │ │
│  └──────────────┘  └──────┬───────┘  └──────────────────────┘ │
│                           │                                    │
│                    ┌──────▼───────┐                            │
│                    │ Tech Detect  │                            │
│                    │              │                            │
│                    │regex patterns│                            │
│                    │on headers    │                            │
│                    │→ Apache/Nginx│                            │
│                    │  PHP/CDN etc │                            │
│                    └──────────────┘                            │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  SSL Module  │  │WHOIS Module  │  │  Security Audit      │ │
│  │              │  │              │  │                      │ │
│  │ssl.wrap_     │  │whois.whois() │  │Check 7 security      │ │
│  │socket()      │  │→ registrar,  │  │headers present:      │ │
│  │getpeercert() │  │  dates,      │  │HSTS, CSP, X-Frame,   │ │
│  │→ cert info,  │  │  nameservers │  │X-Content-Type, etc.  │ │
│  │  TLS version │  │              │  │→ grade A–D           │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │  DISPLAY & FORMAT        │
                    │                         │
                    │  tabulate → tables       │
                    │  colorama → colours      │
                    │  → terminal output       │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  SUMMARY + GRADE         │
                    │  Security Grade: A–D     │
                    │  Stats overview          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  [OPTIONAL] SAVE REPORT  │
                    │  JSON file with all data │
                    └─────────────────────────┘

OUTPUT:
  ├── Colour terminal tables for all 7 modules
  └── scan_<hostname>_<timestamp>.json  (if --save flag used)
```

---

## Module Definitions & Learning

### 1. IP Address Resolution

**Definition:**  
IP Address Resolution is the process of converting a human-readable domain name (like `example.com`) into its numeric IP address (like `93.184.216.34`) using the DNS system. Every device on the internet is identified by an IP address; domain names are just convenient aliases.

**How it works in this tool:**
```python
socket.getaddrinfo(hostname, None)
```
- Queries the operating system's DNS resolver
- Returns both IPv4 (AF_INET) and IPv6 (AF_INET6) addresses
- Multiple IPs may be returned (load balancing, CDN)

**What you learn:**
- The actual server IP(s) behind a domain
- Whether the site uses IPv6
- How many servers handle the domain (load balancing clue)
- The hosting provider (via IP geolocation/WHOIS)

---

### 2. HTTP Headers

**Definition:**  
HTTP (HyperText Transfer Protocol) Headers are key-value metadata pairs transmitted at the beginning of every HTTP request and response. They carry critical information about the communication: content type, encoding, caching rules, security policies, cookies, and server identity — all before the page body is sent.

**How it works in this tool:**
```python
requests.get(url, allow_redirects=True)
response.headers  # dict of all response headers
```

**Key headers explained:**

| Header | Meaning |
|--------|---------|
| `Server` | Web server software (Apache, Nginx, IIS) |
| `Content-Type` | Type of content returned (text/html, etc.) |
| `Cache-Control` | How long browsers/proxies should cache the response |
| `Set-Cookie` | Server sets cookies on the client |
| `Location` | Redirect destination URL |
| `X-Powered-By` | Backend language/framework (PHP, Express) |
| `ETag` | Version identifier for caching |

**What you learn:**
- What software runs the web server
- How caching is configured
- Whether redirects are happening and where
- Backend technology leaks via X-Powered-By

---

### 3. Server Technology Detection

**Definition:**  
Technology Fingerprinting (or Tech Stack Detection) is the process of identifying what software components power a website by examining the characteristic patterns left in HTTP response headers. Different web servers, programming languages, CDNs, and frameworks each leave unique "fingerprints."

**How it works in this tool:**
```python
# Example signature check
re.search(r"Apache", headers.get("Server", ""))
re.search(r"PHP", headers.get("X-Powered-By", ""))
```

**Signatures detected:**

| Technology | Detection Header | Pattern |
|-----------|-----------------|---------|
| Apache | `Server` | `Apache` |
| Nginx | `Server` | `nginx` |
| Cloudflare | `Server` or `CF-RAY` | `cloudflare` |
| PHP | `X-Powered-By` | `PHP/x.x` |
| ASP.NET | `X-Powered-By` | `ASP.NET` |
| Varnish CDN | `X-Varnish` | `Varnish` |

**What you learn:**
- The web server software (and sometimes version)
- Backend programming language
- CDN/proxy layer presence
- Framework clues for further research

---

### 4. DNS Records

**Definition:**  
The Domain Name System (DNS) is the internet's distributed phonebook. DNS records are entries in this global database that map domain names to various resources. Different record types serve different purposes and reveal different aspects of how a domain is configured.

**How it works in this tool:**
```python
dns.resolver.resolve(hostname, "A")    # IPv4 address
dns.resolver.resolve(hostname, "MX")   # Mail servers
dns.resolver.resolve(hostname, "TXT")  # Text records (SPF, DKIM)
```

**Record types explained:**

| Record | Full Name | Purpose | Example |
|--------|-----------|---------|---------|
| `A` | Address | Domain → IPv4 | `93.184.216.34` |
| `AAAA` | IPv6 Address | Domain → IPv6 | `2606:2800::1` |
| `MX` | Mail Exchange | Who handles email | `mail.example.com` |
| `NS` | Name Server | Authoritative DNS servers | `ns1.example.com` |
| `TXT` | Text | SPF, DKIM, domain verification | `v=spf1 include:...` |
| `CNAME` | Canonical Name | Alias to another domain | `www → example.com` |
| `SOA` | Start of Authority | Zone admin info | Serial, refresh, retry |

**What you learn:**
- All IP addresses associated with the domain
- Which company handles their email (Google Workspace? Microsoft 365?)
- Email security configuration (SPF prevents spoofing)
- CDN usage (CNAME chains reveal CDN providers)
- DNS hosting provider (NS records)

---

### 5. SSL/TLS Certificate

**Definition:**  
SSL (Secure Sockets Layer) / TLS (Transport Layer Security) certificates are digital documents that serve two purposes: (1) they establish an encrypted tunnel between client and server so data cannot be intercepted, and (2) they authenticate the server's identity, proving the site is genuinely who it claims to be. The certificate is issued and signed by a trusted Certificate Authority (CA).

**How it works in this tool:**
```python
ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
    s.connect((hostname, 443))
    cert = s.getpeercert()
    tls_version = s.version()  # TLS 1.2 or TLS 1.3
```

**Certificate fields explained:**

| Field | Meaning |
|-------|---------|
| Common Name (CN) | Primary domain the cert covers |
| Organization | Company/entity that owns the cert |
| Issuer | Certificate Authority that signed it |
| Valid From/Until | Certificate validity period |
| Serial Number | Unique ID for the cert |
| Subject Alt Names | All additional domains covered |
| TLS Version | Protocol version (TLS 1.2, 1.3) |
| Cipher Suite | Encryption algorithm negotiated |

**What you learn:**
- Whether the site has a valid, trusted certificate
- How many days until expiry (important for monitoring)
- All domains covered by the certificate (SAN enumeration)
- Hosting/CDN provider (often in the cert organization)
- Security protocol versions (TLS 1.0/1.1 = outdated/insecure)

---

### 6. WHOIS Lookup

**Definition:**  
WHOIS (pronounced "who is") is a query-and-response protocol used to query databases that store information about registered internet resources, particularly domain names. It returns registration metadata: who registered the domain, when, when it expires, and which name servers it uses.

**How it works in this tool:**
```python
import whois
w = whois.whois(hostname)
w.registrar        # e.g. "GoDaddy.com, LLC"
w.creation_date    # When domain was first registered
w.expiration_date  # When registration expires
w.name_servers     # DNS servers managing the domain
```

**WHOIS fields explained:**

| Field | Meaning |
|-------|---------|
| Registrar | Company where the domain is registered |
| Creation Date | When the domain was first registered |
| Expiration Date | When the registration expires |
| Updated Date | Last modification to the record |
| Name Servers | DNS servers that answer for this domain |
| Status | Domain lock/transfer status |
| Emails | Abuse/admin contact emails |
| Organization | Registrant organization |

**What you learn:**
- Domain age (old domains are generally more trusted)
- When it might expire (competitor monitoring)
- Registrar used
- Whether WHOIS privacy protection is enabled
- Abuse contact for reporting issues

---

### 7. Security Headers Audit

**Definition:**  
Security Response Headers are a set of HTTP headers that instruct the browser to enable built-in security mechanisms. When configured correctly, they protect users from a wide range of attacks including cross-site scripting (XSS), clickjacking, man-in-the-middle attacks, and data injection. Their absence is a common finding in security audits.

**How it works in this tool:**
```python
# Check each recommended security header
for header in SECURITY_HEADERS:
    present = header.lower() in response_headers
    # Grade based on missing count
```

**Security headers explained:**

| Header | Attack Prevented | Example Value |
|--------|-----------------|---------------|
| `Strict-Transport-Security` | HTTP downgrade / MITM | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | XSS, data injection | `default-src 'self'` |
| `X-Frame-Options` | Clickjacking | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | MIME sniffing attacks | `nosniff` |
| `Referrer-Policy` | Privacy / referrer leakage | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Feature/API abuse | `geolocation=(), microphone=()` |
| `X-XSS-Protection` | Legacy XSS (deprecated) | `1; mode=block` |

**Grading system:**

| Grade | Missing Headers | Meaning |
|-------|----------------|---------|
| A | 0 | Excellent security posture |
| B | 1–2 | Good, minor improvements needed |
| C | 3–4 | Average, several gaps |
| D | 5+ | Poor security headers configuration |

---

## Output & Report

### Terminal Output
All results are displayed in formatted tables with color coding:
- 🟢 **Green** = Good/Present/Valid
- 🟡 **Yellow** = Warning/Missing/Expiring soon
- 🔴 **Red** = Error/Expired/Critical

### JSON Report (`--save` flag)
When `--save` is used, a JSON file is created:
```
scan_example_com_20241215_143022.json
```

**Report structure:**
```json
{
  "target": "example.com",
  "hostname": "example.com",
  "scanned_at": "2024-12-15 14:30:22",
  "ip": { "ipv4": [...], "ipv6": [...] },
  "http": { "status_code": 200, "headers": {...} },
  "technologies": [...],
  "dns": { "A": [...], "MX": [...], ... },
  "ssl": { "valid_until": "...", "days_until_expiry": 365, ... },
  "whois": { "registrar": "...", "creation_date": "...", ... },
  "security_audit": [...]
}
```

---

## Sample Output

```
═══════════════════════════════════════════════════════════════════
  🌍  WEBSITE INFORMATION SCANNER
  Recon Tool — IP · Headers · DNS · WHOIS · SSL · Tech Stack
═══════════════════════════════════════════════════════════════════
  Target   : https://example.com
  Hostname : example.com
  Started  : 2024-12-15 14:30:22

[*] Resolving IP address...
[*] Fetching HTTP headers...
[*] Detecting technologies...

───────────────────────────────────────────────────────
  1. IP ADDRESS RESOLUTION
───────────────────────────────────────────────────────
╭───────┬─────────────────┬──────────────────────────────────╮
│ Type  │ Address         │                                  │
├───────┼─────────────────┤                                  │
│ IPv4  │ 93.184.216.34   │                                  │
│ IPv6  │ 2606:2800::1    │                                  │
╰───────┴─────────────────┴──────────────────────────────────╯

───────────────────────────────────────────────────────
  7. SECURITY HEADERS AUDIT
───────────────────────────────────────────────────────
╭──────────────────────────────────┬───────────┬────────────────────╮
│ Security Header                  │ Status    │ Purpose            │
├──────────────────────────────────┼───────────┼────────────────────┤
│ Strict-Transport-Security        │ ✅ YES    │ Enforces HTTPS     │
│ Content-Security-Policy          │ ❌ MISSING│ Prevents XSS       │
│ X-Frame-Options                  │ ✅ YES    │ Prevents clickjack │
╰──────────────────────────────────┴───────────┴────────────────────╯

Security Grade : B  (1/7 headers missing)
```

---

## Educational Definitions Glossary

| Term | Definition |
|------|-----------|
| **Passive Recon** | Gathering info without directly probing the target; uses public data |
| **Active Recon** | Sending probes/payloads to a target (NOT what this tool does) |
| **Fingerprinting** | Identifying software/version from characteristic responses |
| **IP Address** | Numeric identifier for a device on a network (IPv4 or IPv6) |
| **DNS** | Distributed database mapping domain names to resources |
| **HTTP** | Protocol for transferring web data between client and server |
| **HTTPS** | HTTP secured with TLS encryption |
| **TLS** | Transport Layer Security — encryption protocol for HTTPS |
| **Certificate Authority** | Trusted entity that signs SSL certificates (Let's Encrypt, DigiCert) |
| **WHOIS** | Protocol to query domain registration databases |
| **CDN** | Content Delivery Network — servers distributed globally to reduce latency |
| **HSTS** | HTTP Strict Transport Security — forces HTTPS on browsers |
| **CSP** | Content Security Policy — whitelist of allowed content sources |
| **XSS** | Cross-Site Scripting — injecting malicious scripts into web pages |
| **Clickjacking** | Tricking users into clicking on hidden/overlaid elements |
| **MIME Sniffing** | Browser guessing content type — exploited in attacks |
| **SPF** | Sender Policy Framework — DNS record authorizing mail senders |
| **SAN** | Subject Alternative Name — additional hostnames on one certificate |
| **MX Record** | Mail Exchange record — points to mail servers for a domain |
| **NS Record** | Name Server record — authoritative DNS servers for a domain |

---

## Ethics & Legal Notice

> ⚠️ **IMPORTANT — USE RESPONSIBLY**

This tool only performs **passive reconnaissance** using:
- Standard DNS queries (same as any browser)
- HTTP GET requests (same as any browser)
- SSL handshakes (same as any browser)
- WHOIS lookups (public database)

**You should ONLY scan:**
- Websites you own or operate
- Websites you have explicit written permission to test
- Public websites for legitimate educational purposes

**Never use this tool to:**
- Scan systems without authorization
- Gather intelligence for malicious attacks
- Violate any applicable computer crime laws

This tool is for **education, security auditing of your own assets, and legitimate research only.**

---

## File Structure

```
website_scanner/
├── website_scanner.py    ← Main scanner script (all modules)
├── requirements.txt      ← Python dependencies
└── README.md             ← This documentation file
```

---

*Built for educational purposes as part of the Security & Recon Toolkit.*
