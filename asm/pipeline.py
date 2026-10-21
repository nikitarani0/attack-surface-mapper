import asyncio

from asm import db
from asm.modules import (
    subdomain_enum, dns_resolve, http_probe,
    port_scan, cloud_discovery, endpoint_secret, correlate, report,
)


async def run_full_scan(domain: str, skip_ports: bool = False) -> int:
    """
    Full ASM pipeline end-to-end. Returns the scan_id.
    Port scanning is OFF by default on the chained run because it's the one
    intrusive step — opt in explicitly with --ports.
    """
    print(f"\n{'='*60}")
    print(f"  ASM full scan: {domain}")
    print(f"{'='*60}\n")

    # Stage 1: subdomain enum (creates the scan row + returns its id)
    scan_id = await subdomain_enum.run_subdomain_enum(domain)

    # Stage 2: DNS resolution (filters to live subdomains)
    await dns_resolve.run_dns_resolution(scan_id)

    # Stage 3: HTTP probing (which hosts serve web)
    await http_probe.run_http_probe(scan_id)

    # Stage 4: port scanning (INTRUSIVE — opt-in only)
    if not skip_ports:
        await port_scan.run_port_scan(scan_id)
    else:
        print("[pipeline] Port scan skipped (default). Use --ports to enable.")

    # Stage 5: cloud asset discovery (your differentiator)
    await cloud_discovery.run_cloud_discovery(scan_id)

    # Stage 6: endpoint + secret recon
    await endpoint_secret.run_endpoint_secret(scan_id)

    # Stage 7: correlation engine (pure logic → findings)
    correlate.run_correlation(scan_id)

    # Stage 8: reporting
    report.generate_reports(scan_id)

    print(f"\n{'='*60}")
    print(f"  Scan #{scan_id} complete. Reports in ./reports/")
    print(f"{'='*60}\n")
    return scan_id
