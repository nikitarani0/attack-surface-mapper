# Attack Surface Mapper (ASM)

A cloud-focused reconnaissance and attack-surface correlation tool for authorized bug bounty and penetration testing. Given a domain, ASM maps the external attack surface — subdomains, live hosts, services, cloud assets, endpoints, and exposed secrets — then **correlates across them** to surface prioritized, exploitable findings.

Built in async Python. It orchestrates recon into one pipeline and reasons about the results, rather than dumping raw scanner output.

---

## What makes it different

Most recon tools list assets. ASM correlates them. Its rule engine flags:

- **Subdomain takeover candidates** — dangling DNS pointing at deprovisioned cloud resources
- **SSRF-to-IMDS candidates** — URL-fetching endpoints on cloud-hosted assets (metadata credential-theft surface)
- **Exposed secrets** — AWS keys, tokens, and credentials in client-side JS (redacted on capture)
- **Public cloud storage** and **exposed risky services** (databases, RDP, VNC, etc.)

Each finding records *why* it fired (`correlation_type`), so the output is decision-support, not noise.

---

## Pipeline

```
domain → subdomain enum (6 passive sources) → DNS resolution → HTTP probe
       → port scan (opt-in) → cloud discovery → endpoint + secret recon
       → correlation engine → JSON + Markdown report
```

Every stage persists to SQLite, keyed by scan, so stages are independently re-runnable — re-probe without re-enumerating, re-correlate without re-scanning.

---

## Features

| Module | What it does |
|---|---|
| Subdomain enumeration | 6 passive sources (crt.sh, HackerTarget, Anubis, AlienVault OTX, RapidDNS, VirusTotal), merged + deduped, fail-soft |
| DNS resolution | Async A-record resolution to filter live subdomains and record IPs |
| HTTP probing | HTTPS-first live-host detection: status, title, server, tech, WAF |
| Port + service scan | nmap service/version detection on unique IPs (opt-in, rate-limited) |
| Cloud discovery | Classifies AWS/Azure/GCP assets, checks S3 public exposure, flags takeover candidates |
| Endpoint + secret recon | Crawls hosts and parses JavaScript for endpoints and exposed secrets |
| Correlation engine | Cross-references all tables into prioritized, severity-ranked findings |
| Reporting | JSON (complete) + Markdown (human-readable), findings-first |

---

## Install

```bash
git clone https://github.com/nikitarani0/attack-surface-mapper
cd attack-surface-mapper
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

Optional — add a free VirusTotal API key to `.env` for an extra enumeration source:

```
VIRUSTOTAL_API_KEY=your_key
```

Requires `nmap` on PATH for the optional port-scanning stage:

```bash
sudo apt install nmap
```

---

## Usage

```bash
asm scan --domain example.com          # full scan (safe default, no port scan)
asm scan --domain example.com --ports  # include port scanning (authorized targets only)
asm list                               # list past scans
asm report --scan-id 3                 # regenerate reports for a scan
```

Reports are written to `reports/` as JSON (complete data) and Markdown (readable summary, findings first).

---

## Responsible use

This tool is for **authorized testing only** — targets you own or have explicit permission to test (bug bounty scope, signed engagement).

- **Detect, don't exploit.** ASM identifies exposure (public buckets, exposed secrets, SSRF candidates) and stops. It never uses a found credential, writes to a bucket, or exploits a candidate — those are manual, authorized steps for the operator.
- Secrets are **redacted on capture**; the database never stores a usable credential.
- Port scanning is **opt-in** (`--ports`) and rate-limited.
- Correlation findings are **candidates for manual review**, not confirmed vulnerabilities.

Unauthorized scanning may be illegal under laws such as the CFAA. You are responsible for staying in scope.

---

## Tech stack

Python 3.11+ · asyncio · aiohttp · aiodns · nmap · SQLite

---

## Roadmap

- CNAME-chain resolution for cloud classification (catch indirect cloud assets that don't reveal the provider in the hostname)
- Optional httpx / nuclei integration as faster backends
- Visual attack graph output (networkx)
- PDF report generation

---

## License

MIT
