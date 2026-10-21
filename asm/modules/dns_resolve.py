import asyncio
import aiodns

from asm import db


async def resolve_one(hostname: str, resolver: aiodns.DNSResolver,
                      sem: asyncio.Semaphore) -> tuple[str, bool, str | None]:
    """
    Resolve a single hostname's A record.
    Returns (hostname, resolved_bool, first_ip_or_None).
    The semaphore caps how many DNS queries run at once.
    """
    async with sem:
        try:
            result = await resolver.query(hostname, "A")
            ip = result[0].host if result else None
            return (hostname, True, ip)
        except aiodns.error.DNSError:
            # NXDOMAIN, no A record, timeout, etc. — not live
            return (hostname, False, None)
        except Exception:
            return (hostname, False, None)


async def run_dns_resolution(scan_id: int, concurrency: int = 50) -> None:
    """
    Resolve every subdomain from a scan concurrently, update the DB
    with resolved status + IP. Caps concurrency with a semaphore.
    """
    rows = db.get_subdomains(scan_id)
    hostnames = [r["hostname"] for r in rows]

    if not hostnames:
        print("[dns] No subdomains to resolve — run subdomain enum first")
        return

    print(f"[dns] Resolving {len(hostnames)} subdomains (concurrency={concurrency})...")

    resolver = aiodns.DNSResolver(timeout=5, tries=2)
    sem = asyncio.Semaphore(concurrency)

    tasks = [resolve_one(h, resolver, sem) for h in hostnames]
    results = await asyncio.gather(*tasks)

    live = 0
    for hostname, resolved, ip in results:
        db.update_subdomain_resolution(scan_id, hostname, resolved, ip)
        if resolved:
            live += 1

    print(f"[dns] Done: {live} live / {len(hostnames)} total resolved")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.dns_resolve <scan_id>")
        sys.exit(1)
    scan_id = int(sys.argv[1])
    asyncio.run(run_dns_resolution(scan_id))
