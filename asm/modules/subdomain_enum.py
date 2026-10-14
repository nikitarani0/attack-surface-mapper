import asyncio
import json
import aiohttp

from asm import db


async def fetch_crtsh(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    Query crt.sh's JSON API for certificates issued to *.domain.
    Returns a deduplicated set of subdomains found in certificate CNs/SANs.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[crt.sh] Non-200 response: {resp.status}")
                return subdomains
            text = await resp.text()
            data = json.loads(text)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[crt.sh] Request failed: {e}")
        return subdomains
    except json.JSONDecodeError:
        print("[crt.sh] Failed to parse response JSON")
        return subdomains

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(domain):
                subdomains.add(name)

    return subdomains


async def run_subdomain_enum(domain: str) -> int:
    """Day 1 pipeline: init DB, create scan, fetch crt.sh, persist."""
    db.init_db()
    scan_id = db.create_scan(domain)
    print(f"[+] Scan #{scan_id} started for {domain}")

    async with aiohttp.ClientSession() as session:
        crtsh_results = await fetch_crtsh(domain, session)

    new_count = db.insert_subdomains(scan_id, crtsh_results, source="crt.sh")
    print(f"[+] crt.sh: {len(crtsh_results)} found, {new_count} new → saved")

    db.finish_scan(scan_id)
    return scan_id


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(run_subdomain_enum(target))
