import asyncio
import re
import aiohttp

from asm import db

# --- Secret detection patterns ---
# Each: name -> (regex, severity). Patterns are intentionally specific to
# cut false positives. Cloud keys are the high-value targets here.
SECRET_PATTERNS = {
    "aws_access_key":   (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "critical"),
    "aws_secret_key":   (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "critical"),
    "google_api_key":   (re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "high"),
    "slack_token":      (re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"), "high"),
    "github_token":     (re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"), "high"),
    "stripe_key":       (re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b"), "critical"),
    "jwt":              (re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium"),
    "private_key":      (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "critical"),
}

# --- Endpoint extraction from JS ---
# Find quoted paths and full URLs that look like API routes.
ENDPOINT_PATTERNS = [
    re.compile(r"""['"](/[a-zA-Z0-9_\-/.]+(?:\?[a-zA-Z0-9_\-=&]*)?)['"]"""),  # "/api/v1/users"
    re.compile(r"""['"](https?://[a-zA-Z0-9_\-./]+(?:/[a-zA-Z0-9_\-/.]*)?)['"]"""),  # full URLs
]

# Find <script src="..."> references to pull JS files.
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)


def redact(secret: str) -> str:
    """Show only enough to identify, never the full secret."""
    if len(secret) <= 8:
        return secret[:2] + "****"
    return secret[:4] + "****" + secret[-4:]


def scan_for_secrets(text: str, location: str, scan_id: int) -> int:
    """Run all secret patterns over text; store hits redacted. Returns count."""
    count = 0
    for name, (pattern, severity) in SECRET_PATTERNS.items():
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            db.insert_secret(scan_id, name, redact(value), location, severity)
            count += 1
    return count


def extract_endpoints(text: str) -> set[str]:
    """Pull candidate endpoints/paths from JS or HTML text."""
    found = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.findall(text):
            # filter noise: skip image/css/font static assets
            if any(match.lower().endswith(ext) for ext in
                   (".png", ".jpg", ".svg", ".css", ".woff", ".woff2", ".gif", ".ico")):
                continue
            if len(match) > 3:
                found.add(match)
    return found


async def fetch_text(url: str, session: aiohttp.ClientSession,
                     sem: asyncio.Semaphore) -> str | None:
    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as resp:
                if resp.status == 200:
                    return await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
    return None


async def process_host(base_url: str, session: aiohttp.ClientSession,
                       sem: asyncio.Semaphore, scan_id: int) -> tuple[int, int]:
    """Crawl one host: fetch page, find JS, scan page + JS for endpoints & secrets."""
    endpoints_found = 0
    secrets_found = 0

    html = await fetch_text(base_url, session, sem)
    if not html:
        return (0, 0)

    # 1. Scan the HTML page itself
    secrets_found += scan_for_secrets(html, base_url, scan_id)
    for ep in extract_endpoints(html):
        db.insert_endpoint(scan_id, None, ep, None, None, source=base_url)
        endpoints_found += 1

    # 2. Find and fetch JS files referenced on the page
    js_urls = []
    for src in SCRIPT_SRC_RE.findall(html):
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("/"):
            # relative → make absolute against the base host
            from urllib.parse import urljoin
            js_urls.append(urljoin(base_url, src))

    # fetch JS files concurrently (cap to first 15 per host to stay polite)
    js_texts = await asyncio.gather(
        *[fetch_text(u, session, sem) for u in js_urls[:15]]
    )

    for js_url, js_text in zip(js_urls[:15], js_texts):
        if not js_text:
            continue
        secrets_found += scan_for_secrets(js_text, js_url, scan_id)
        for ep in extract_endpoints(js_text):
            db.insert_endpoint(scan_id, None, ep, None, None, source=js_url)
            endpoints_found += 1

    return (endpoints_found, secrets_found)


async def run_endpoint_secret(scan_id: int, concurrency: int = 20) -> None:
    """For every live web host, extract endpoints + hunt secrets in page & JS."""
    hosts = db.get_hosts(scan_id)
    urls = [h["url"] for h in hosts]

    if not urls:
        print("[endpoints] No live hosts — run HTTP probe first")
        return

    print(f"[endpoints] Crawling {len(urls)} hosts for endpoints + secrets...")

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) asm-recon/0.1"}

    async with aiohttp.ClientSession(headers=headers) as session:
        results = await asyncio.gather(
            *[process_host(u, session, sem, scan_id) for u in urls]
        )

    total_ep = sum(r[0] for r in results)
    total_sec = sum(r[1] for r in results)

    print(f"[endpoints] Done: {total_ep} endpoints, {total_sec} secrets flagged")
    if total_sec:
        print(f"[endpoints] ⚠ {total_sec} SECRET(S) found — verify + report, NEVER use them")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.endpoint_secret <scan_id>")
        sys.exit(1)
    asyncio.run(run_endpoint_secret(int(sys.argv[1])))
