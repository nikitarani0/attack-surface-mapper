import asyncio
import aiohttp

from asm import db

# CNAME / hostname patterns that reveal cloud-hosted assets.
CLOUD_PATTERNS = {
    "aws-s3": [".s3.amazonaws.com", ".s3-website", ".s3.", "s3-"],
    "aws-cloudfront": [".cloudfront.net"],
    "aws-elb": [".elb.amazonaws.com", ".elasticbeanstalk.com"],
    "azure-blob": [".blob.core.windows.net"],
    "azure-web": [".azurewebsites.net", ".cloudapp.azure.com"],
    "gcp-storage": [".storage.googleapis.com"],
    "gcp-appengine": [".appspot.com"],
    "heroku": [".herokuapp.com"],
    "github-pages": [".github.io"],
}

# Fingerprints for dangling-DNS takeover: if a subdomain CNAMEs to one of these
# services AND the service returns a "not claimed" signature, it's a takeover candidate.
# (Signatures are simplified from the can-i-take-over-xyz project.)
TAKEOVER_SIGNATURES = {
    "aws-s3": "NoSuchBucket",
    "azure-blob": "The specified container does not exist",
    "github-pages": "There isn't a GitHub Pages site here",
    "heroku": "No such app",
    "gcp-storage": "NoSuchKey",
}


def classify_cloud(hostname: str) -> str | None:
    """Return provider/type if hostname matches a known cloud pattern."""
    h = hostname.lower()
    for asset_type, patterns in CLOUD_PATTERNS.items():
        for p in patterns:
            if p in h:
                return asset_type
    return None


async def check_s3_public(bucket_url: str, session: aiohttp.ClientSession) -> bool:
    """
    Safe public-exposure check: a public S3 bucket returns a listing (200)
    or ListBucketResult; a private one returns AccessDenied (403).
    We only GET — never write, never enumerate contents.
    """
    try:
        async with session.get(bucket_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            text = await resp.text(errors="ignore")
            if resp.status == 200 and "ListBucketResult" in text:
                return True
            return False
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


async def check_takeover(hostname: str, asset_type: str,
                         session: aiohttp.ClientSession) -> bool:
    """
    Fetch the host and look for a 'not claimed' signature for its cloud service.
    Presence of the signature = dangling DNS = takeover candidate (flag for manual review).
    """
    signature = TAKEOVER_SIGNATURES.get(asset_type)
    if not signature:
        return False

    for scheme in ("https", "http"):
        try:
            async with session.get(f"{scheme}://{hostname}",
                                   timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as resp:
                text = await resp.text(errors="ignore")
                if signature.lower() in text.lower():
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return False


async def run_cloud_discovery(scan_id: int, concurrency: int = 20) -> None:
    """Classify cloud-hosted subdomains, check S3 exposure + takeover candidates."""
    rows = db.get_subdomains(scan_id)
    hostnames = [r["hostname"] for r in rows]

    if not hostnames:
        print("[cloud] No subdomains — run subdomain enum first")
        return

    print(f"[cloud] Scanning {len(hostnames)} subdomains for cloud assets...")

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) asm-recon/0.1"}

    async def process(hostname: str):
        async with sem:
            asset_type = classify_cloud(hostname)
            if not asset_type:
                return None

            provider = asset_type.split("-")[0]  # aws / azure / gcp / etc.
            public = False
            takeover = False

            async with aiohttp.ClientSession(headers=headers) as session:
                if asset_type == "aws-s3":
                    public = await check_s3_public(f"https://{hostname}", session)
                takeover = await check_takeover(hostname, asset_type, session)

            return {
                "type": asset_type, "identifier": hostname,
                "provider": provider, "public": public, "takeover": takeover,
            }

    results = await asyncio.gather(*[process(h) for h in hostnames])

    found = public_count = takeover_count = 0
    for r in results:
        if r:
            found += 1
            db.insert_cloud_asset(scan_id, r["type"], r["identifier"],
                                  r["provider"], r["public"], r["takeover"])
            if r["public"]:
                public_count += 1
            if r["takeover"]:
                takeover_count += 1

    print(f"[cloud] Done: {found} cloud assets | "
          f"{public_count} public S3 | {takeover_count} takeover candidates")
    if takeover_count:
        print(f"[cloud] ⚠ {takeover_count} TAKEOVER CANDIDATE(S) — verify manually before reporting")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.cloud_discovery <scan_id>")
        sys.exit(1)
    asyncio.run(run_cloud_discovery(int(sys.argv[1])))
