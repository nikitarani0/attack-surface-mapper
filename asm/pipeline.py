import asyncio

from asm import db
from asm.modules import (
    subdomain_enum, dns_resolve, http_probe,
    port_scan, cloud_discovery, endpoint_secret, correlate, report,
)


async def run_full_scan(domain: str, skip_ports: bool = False,
                        passive: bool = False) -> int:
    """
    Full ASM pipeline end-to-end. Returns the scan_id.

    passive=True → only stages that DO NOT send requests to the target:
      subdomain enum (3rd-party sources), DNS resolution (public resolvers),
      cloud classification (hostname-based), correlation.
      Skips HTTP probe, port scan, and endpoint/secret crawl.
      Safe for programs that ban automated scanners/traffic against them.
    """
    mode = "PASSIVE (no traffic to target)" if passive else "FULL"
    print(f"\n{'='*60}")
    print(f"  ASM {mode} scan: {domain}")
    print(f"{'='*60}\n")

    # Stage 1: subdomain enum — queries crt.sh/VT/etc, not the target
    scan_id = await subdomain_enum.run_subdomain_enum(domain)

    # Stage 2: DNS resolution — public resolvers, not the target's web servers
    await dns_resolve.run_dns_resolution(scan_id)

    if passive:
        # Cloud classification works off hostnames already in the DB —
        # but the S3 public-check and takeover-check DO fetch the asset,
        # so run cloud discovery in its hostname-only form.
        await cloud_discovery.run_cloud_discovery(scan_id, passive=True)
        correlate.run_correlation(scan_id)
        report.generate_reports(scan_id)
        print(f"\n{'='*60}")
        print(f"  Scan #{scan_id} complete (passive). Reports in ./reports/")
        print(f"  No requests were sent to the target.")
        print(f"{'='*60}\n")
        return scan_id

    # --- active stages (only in full mode) ---
    await http_probe.run_http_probe(scan_id)

    if not skip_ports:
        await port_scan.run_port_scan(scan_id)
    else:
        print("[pipeline] Port scan skipped. Use --ports to enable.")

    await cloud_discovery.run_cloud_discovery(scan_id)
    await endpoint_secret.run_endpoint_secret(scan_id)
    correlate.run_correlation(scan_id)
    report.generate_reports(scan_id)

    print(f"\n{'='*60}")
    print(f"  Scan #{scan_id} complete. Reports in ./reports/")
    print(f"{'='*60}\n")
    return scan_id
