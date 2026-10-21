import re

from asm import db

# Endpoint parameter names that commonly indicate server-side URL fetching
# → prime SSRF candidates. Your specialty: SSRF → cloud metadata (IMDS).
SSRF_PARAM_HINTS = [
    "url", "uri", "redirect", "redirect_url", "callback", "callback_url",
    "next", "dest", "destination", "target", "link", "load", "fetch",
    "domain", "site", "host", "proxy", "image_url", "img", "file", "path",
]

# Interesting path keywords that merit a flag on their own.
SENSITIVE_PATH_HINTS = [
    "admin", "internal", "debug", "config", "backup", "test", "dev",
    "staging", "api-docs", "swagger", "graphql", "actuator", "metrics",
    ".git", ".env", "phpinfo",
]


def correlate_takeovers(scan_id: int) -> int:
    """Rule 1: cloud_assets already flagged as takeover candidates → critical findings."""
    count = 0
    for asset in db.get_cloud_assets(scan_id):
        if asset["takeover_candidate"]:
            db.insert_finding(
                scan_id,
                title=f"Subdomain takeover candidate: {asset['identifier']}",
                severity="critical",
                category="subdomain-takeover",
                evidence=f"{asset['identifier']} ({asset['provider']} {asset['type']}) "
                         f"shows unclaimed-service signature",
                correlation_type="dangling_dns_takeover",
            )
            count += 1
    return count


def correlate_public_buckets(scan_id: int) -> int:
    """Rule 2: publicly-listable cloud storage → high finding."""
    count = 0
    for asset in db.get_cloud_assets(scan_id):
        if asset["public"]:
            db.insert_finding(
                scan_id,
                title=f"Publicly accessible storage: {asset['identifier']}",
                severity="high",
                category="cloud-exposure",
                evidence=f"{asset['identifier']} returned a public listing",
                correlation_type="public_cloud_storage",
            )
            count += 1
    return count


def correlate_secrets(scan_id: int) -> int:
    """Rule 3: any discovered secret → finding at its own severity."""
    count = 0
    for secret in db.get_secrets(scan_id):
        db.insert_finding(
            scan_id,
            title=f"Exposed {secret['type']} in client-side code",
            severity=secret["severity"],
            category="exposed-secret",
            evidence=f"{secret['type']} ({secret['value_redacted']}) at {secret['location']}",
            correlation_type="exposed_secret_in_js",
        )
        count += 1
    return count


def correlate_ssrf_candidates(scan_id: int) -> int:
    """
    Rule 4 (YOUR specialty): endpoints with URL-ish params → SSRF-to-IMDS candidates.
    Higher priority when the host is cloud-hosted (metadata endpoint reachable).
    """
    count = 0
    cloud_hosts = {a["identifier"] for a in db.get_cloud_assets(scan_id)}

    for ep in db.get_endpoints(scan_id):
        url = ep["url"].lower()
        # does the endpoint expose a URL-fetching parameter?
        matched_param = next((p for p in SSRF_PARAM_HINTS
                              if re.search(rf"[?&]{re.escape(p)}=", url) or f"/{p}/" in url
                              or url.endswith(f"/{p}")), None)
        if not matched_param:
            # also catch param names appearing as query keys without values
            matched_param = next((p for p in SSRF_PARAM_HINTS if f"{p}=" in url), None)
        if matched_param:
            # elevate severity if the source host is cloud-hosted
            source = (ep["source"] or "").lower()
            is_cloud = any(ch in source for ch in cloud_hosts) if cloud_hosts else False
            severity = "high" if is_cloud else "medium"
            db.insert_finding(
                scan_id,
                title=f"Potential SSRF vector (param: {matched_param})",
                severity=severity,
                category="ssrf-candidate",
                evidence=f"Endpoint {ep['url']} exposes '{matched_param}' "
                         f"param{' on cloud-hosted asset' if is_cloud else ''} — "
                         f"manual test for SSRF→IMDS",
                correlation_type="ssrf_imds_candidate",
            )
            count += 1
    return count


def correlate_sensitive_paths(scan_id: int) -> int:
    """Rule 5: endpoints hitting sensitive path keywords → low/medium findings."""
    count = 0
    seen = set()  # dedupe by (keyword, host) to avoid flood
    for ep in db.get_endpoints(scan_id):
        url = ep["url"].lower()
        for kw in SENSITIVE_PATH_HINTS:
            if kw in url:
                key = (kw, ep["source"])
                if key in seen:
                    continue
                seen.add(key)
                severity = "medium" if kw in (".git", ".env", "admin", "actuator") else "low"
                db.insert_finding(
                    scan_id,
                    title=f"Sensitive path exposed: '{kw}'",
                    severity=severity,
                    category="sensitive-path",
                    evidence=f"{ep['url']} (found via {ep['source']})",
                    correlation_type="sensitive_path_exposure",
                )
                count += 1
                break  # one finding per endpoint is enough
    return count


def correlate_risky_services(scan_id: int) -> int:
    """Rule 6: exposed databases/admin services on open ports → high findings."""
    RISKY = {
        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
        9200: "Elasticsearch", 3389: "RDP", 5900: "VNC", 23: "Telnet", 1433: "MSSQL",
    }
    count = 0
    for svc in db.get_services(scan_id):
        if svc["port"] in RISKY:
            db.insert_finding(
                scan_id,
                title=f"Exposed {RISKY[svc['port']]} service",
                severity="high",
                category="exposed-service",
                evidence=f"{svc['ip']}:{svc['port']} "
                         f"({svc['service'] or '?'} {svc['version'] or ''})".strip(),
                correlation_type="exposed_risky_service",
            )
            count += 1
    return count


def run_correlation(scan_id: int) -> None:
    """Run all correlation rules, rebuild findings for this scan."""
    print(f"[correlate] Running correlation engine for scan {scan_id}...")
    db.clear_findings(scan_id)  # idempotent: re-running replaces, doesn't stack

    results = {
        "takeover": correlate_takeovers(scan_id),
        "public_buckets": correlate_public_buckets(scan_id),
        "secrets": correlate_secrets(scan_id),
        "ssrf_candidates": correlate_ssrf_candidates(scan_id),
        "sensitive_paths": correlate_sensitive_paths(scan_id),
        "risky_services": correlate_risky_services(scan_id),
    }

    total = sum(results.values())
    print(f"[correlate] Generated {total} findings:")
    for rule, n in results.items():
        if n:
            print(f"    {rule}: {n}")

    # severity summary
    findings = db.get_findings(scan_id)
    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    if sev_counts:
        summary = " | ".join(f"{s}: {c}" for s, c in sev_counts.items())
        print(f"[correlate] By severity → {summary}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.correlate <scan_id>")
        sys.exit(1)
    run_correlation(int(sys.argv[1]))
