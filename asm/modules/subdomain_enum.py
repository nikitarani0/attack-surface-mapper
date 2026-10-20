import asyncio
import json
import aiohttp

from asm import db


async def fetch_crtsh(domain: str, session: aiohttp.ClientSession, retries: int = 3) -> set[str]:
    """
    Query crt.sh's JSON API for certificates issued to *.domain.
    crt.sh is unreliable and often returns 5xx under load, so we retry.
    Returns a deduplicated set of subdomains.
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
            await asyncio.sleep(5)  # back off before retrying

    print("[crt.sh] All attempts failed — crt.sh is likely down right now")
    return subdomains


async def fetch_hackertarget(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """
    Query HackerTarget's free hostsearch API. No API key required.
    Returns a set of subdomains. Free tier is rate-limited but fine for testing.
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

    # Response format is plain text: "subdomain,ip" one per line
    if "error" in text.lower() or "API count exceeded" in text:
        print(f"[hackertarget] API limit or error: {text[:80]}")
        return subdomains

    for line in text.strip().split("\n"):
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain):
                subdomains.add(host)

    return subdomains


async def run_subdomain_enum(domain: str) -> int:
    """Day 1 pipeline: init DB, create scan, fetch passive sources, persist."""
    db.init_db()
    scan_id = db.create_scan(domain)
    print(f"[+] Scan #{scan_id} started for {domain}")

    async with aiohttp.ClientSession() as session:
        # run both sources concurrently
        crtsh_results, ht_results = await asyncio.gather(
            fetch_crtsh(domain, session),
            fetch_hackertarget(domain, session),
        )

    # persist each source separately so you can see which found what
    c1 = db.insert_subdomains(scan_id, crtsh_results, source="crt.sh")
    c2 = db.insert_subdomains(scan_id, ht_results, source="hackertarget")
    print(f"[+] crt.sh: {len(crtsh_results)} found, {c1} new")
    print(f"[+] hackertarget: {len(ht_results)} found, {c2} new")

    total = db.get_subdomains(scan_id)
    print(f"[+] Total unique subdomains saved: {len(total)}")

    db.finish_scan(scan_id)
    return scan_id


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(run_subdomain_enum(target))
