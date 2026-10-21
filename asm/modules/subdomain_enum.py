import asyncio
import json
import re
import aiohttp

from asm import db
from asm import config


async def fetch_crtsh(domain: str, session: aiohttp.ClientSession, retries: int = 3) -> set[str]:
    """
    Query crt.sh's JSON API for certificates issued to *.domain.
    crt.sh is unreliable and often returns 5xx under load, so we retry.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if not text.strip():
                        print(f"[crt.sh] Empty body (attempt {attempt}/{retries})")
                    else:
                        data = json.loads(text)
                        for entry in data:
                            for name in entry.get("name_value", "").split("\n"):
                                name = name.strip().lower()
                                if name.startswith("*."):
                                    name = name[2:]
                                if name.endswith(domain):
                                    subdomains.add(name)
                        print(f"[crt.sh] OK on attempt {attempt}: {len(subdomains)} subdomains")
                        return subdomains
                elif resp.status >= 500:
                    print(f"[crt.sh] Server error {resp.status} (attempt {attempt}/{retries}) — retrying")
                else:
                    print(f"[crt.sh] Unexpected status {resp.status} (attempt {attempt}/{retries})")

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"[crt.sh] Request failed (attempt {attempt}/{retries}): {e}")
        except json.JSONDecodeError:
            print(f"[crt.sh] Bad JSON (attempt {attempt}/{retries})")

        if attempt < retries:
            await asyncio.sleep(5)

    print("[crt.sh] All attempts failed — crt.sh is likely down right now")
    return subdomains


async def fetch_hackertarget(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    HackerTarget hostsearch API. Free, no API key. Rate-limited on free tier.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[hackertarget] Non-200: {resp.status}")
                return subdomains
            text = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[hackertarget] Request failed: {e}")
        return subdomains

    if "error" in text.lower() or "API count exceeded" in text:
        print(f"[hackertarget] API limit or error: {text[:80]}")
        return subdomains

    for line in text.strip().split("\n"):
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain):
                subdomains.add(host)

    return subdomains


async def fetch_anubis(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    Anubis-DB (jldc.me). Free, no API key. Returns JSON array of subdomains.
    """
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) asm-recon/0.1"}
    subdomains = set()

    try:
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[anubis] Non-200: {resp.status}")
                return subdomains
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[anubis] Request failed: {e}")
        return subdomains
    except Exception as e:
        print(f"[anubis] Parse error: {e}")
        return subdomains

    for host in data:
        host = host.strip().lower()
        if host.endswith(domain):
            subdomains.add(host)

    return subdomains


async def fetch_alienvault(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    AlienVault OTX passive DNS. Free, no API key required for this endpoint.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[alienvault] Non-200: {resp.status}")
                return subdomains
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[alienvault] Request failed: {e}")
        return subdomains
    except Exception as e:
        print(f"[alienvault] Parse error: {e}")
        return subdomains

    for record in data.get("passive_dns", []):
        host = record.get("hostname", "").strip().lower()
        if host.endswith(domain):
            subdomains.add(host)

    return subdomains


async def fetch_rapiddns(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    RapidDNS.io. Free, no API key. Returns HTML; subdomains extracted via regex.
    Most fragile source — if the page layout changes, this regex may need updating.
    """
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains = set()

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[rapiddns] Non-200: {resp.status}")
                return subdomains
            text = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[rapiddns] Request failed: {e}")
        return subdomains

    pattern = re.compile(r"[a-zA-Z0-9._-]+\." + re.escape(domain))
    for match in pattern.findall(text):
        host = match.strip().lower()
        if host.endswith(domain):
            subdomains.add(host)

    return subdomains


async def fetch_virustotal(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    VirusTotal passive subdomains. Requires free API key (500/day).
    The /subdomains endpoint is sometimes gated — handled gracefully.
    """
    subdomains = set()
    if not config.VIRUSTOTAL_API_KEY:
        print("[virustotal] No API key set — skipping")
        return subdomains

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    try:
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status in (401, 403):
                print(f"[virustotal] Endpoint gated for free key ({resp.status}) — skipping")
                return subdomains
            if resp.status != 200:
                print(f"[virustotal] Non-200: {resp.status}")
                return subdomains
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[virustotal] Request failed: {e}")
        return subdomains

    for item in data.get("data", []):
        host = item.get("id", "").strip().lower()
        if host.endswith(domain):
            subdomains.add(host)

    return subdomains


async def run_subdomain_enum(domain: str) -> int:
    """Day 2 pipeline: 6 passive sources, concurrent, merged + deduped."""
    db.init_db()
    scan_id = db.create_scan(domain)
    print(f"[+] Scan #{scan_id} started for {domain}")

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            fetch_crtsh(domain, session),
            fetch_hackertarget(domain, session),
            fetch_anubis(domain, session),
            fetch_alienvault(domain, session),
            fetch_rapiddns(domain, session),
            fetch_virustotal(domain, session),
        )

    sources = ["crt.sh", "hackertarget", "anubis", "alienvault", "rapiddns", "virustotal"]
    for src, subs in zip(sources, results):
        new = db.insert_subdomains(scan_id, subs, source=src)
        print(f"[+] {src}: {len(subs)} found, {new} new")

    total = db.get_subdomains(scan_id)
    print(f"[+] Total unique subdomains saved: {len(total)}")

    db.finish_scan(scan_id)
    return scan_id


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(run_subdomain_enum(target))
