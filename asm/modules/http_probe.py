import asyncio
import re
import aiohttp

from asm import db

# Pull <title>...</title> from HTML (case-insensitive, handles newlines)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Lightweight tech fingerprints: header/body signature → technology name.
# This is a starter set — real tools use thousands. We keep it small and honest.
TECH_SIGNATURES = {
    "cloudflare": ("header", "server", "cloudflare"),
    "nginx": ("header", "server", "nginx"),
    "apache": ("header", "server", "apache"),
    "wordpress": ("body", None, "wp-content"),
    "react": ("body", None, "__reactroot"),
    "aws-s3": ("header", "server", "amazons3"),
    "aws-cloudfront": ("header", "via", "cloudfront"),
}


def detect_tech(headers: dict, body: str) -> list[str]:
    """Match response against our starter signature set."""
    found = []
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    lower_body = body.lower()

    for name, (where, header_key, needle) in TECH_SIGNATURES.items():
        if where == "header" and header_key in lower_headers:
            if needle in lower_headers[header_key]:
                found.append(name)
        elif where == "body":
            if needle in lower_body:
                found.append(name)
    return found


def detect_waf(headers: dict) -> str | None:
    """Very light WAF hinting from headers. Not exhaustive."""
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    if "cf-ray" in lower or "cloudflare" in lower.get("server", ""):
        return "cloudflare"
    if "x-akamai" in " ".join(lower.keys()) or "akamai" in lower.get("server", ""):
        return "akamai"
    if "x-amz-cf-id" in lower:
        return "aws-cloudfront"
    return None


async def probe_one(hostname: str, session: aiohttp.ClientSession,
                    sem: asyncio.Semaphore) -> dict | None:
    """
    Try HTTPS first, then HTTP. Return host info dict for the first that responds,
    or None if neither does.
    """
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                    ssl=False,  # don't fail on bad/self-signed certs — we're mapping, not validating
                ) as resp:
                    body = await resp.text(errors="ignore")
                    headers = dict(resp.headers)

                    title_match = TITLE_RE.search(body)
                    title = title_match.group(1).strip()[:200] if title_match else None

                    tech = detect_tech(headers, body)
                    waf = detect_waf(headers)
                    server = headers.get("Server")

                    return {
                        "url": str(resp.url),
                        "status_code": resp.status,
                        "title": title,
                        "tech": ",".join(tech) if tech else None,
                        "waf": waf,
                        "server": server,
                    }
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue  # try next scheme
            except Exception:
                continue

    return None  # neither scheme responded


async def run_http_probe(scan_id: int, concurrency: int = 30) -> None:
    """Probe all resolved subdomains for live web servers; store results."""
    rows = db.get_resolved_subdomains(scan_id)
    hostnames = [r["hostname"] for r in rows]

    if not hostnames:
        print("[http] No resolved subdomains — run DNS resolution first")
        return

    print(f"[http] Probing {len(hostnames)} live hosts (concurrency={concurrency})...")

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) asm-recon/0.1"}

    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [probe_one(h, session, sem) for h in hostnames]
        results = await asyncio.gather(*tasks)

    live_web = 0
    for host_info in results:
        if host_info:
            live_web += 1
            db.insert_host(
                scan_id, None,
                host_info["url"], host_info["status_code"],
                host_info["title"], host_info["tech"],
                host_info["waf"], host_info["server"],
            )

    print(f"[http] Done: {live_web} live web servers / {len(hostnames)} hosts probed")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.http_probe <scan_id>")
        sys.exit(1)
    asyncio.run(run_http_probe(int(sys.argv[1])))
