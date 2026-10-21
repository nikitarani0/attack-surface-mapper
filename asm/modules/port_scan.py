import asyncio
import xml.etree.ElementTree as ET

from asm import db

# Top ports worth checking first. Keep this modest — full 65535 scans are
# slow and abusive. These cover the services that matter most in recon.
TOP_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"


async def scan_ip(ip: str, sem: asyncio.Semaphore) -> list[dict]:
    """
    Run nmap against one IP for TOP_PORTS with service/version detection.
    Parse nmap's XML output. Returns list of open-port dicts.
    """
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sV", "-Pn", "-T3",
                "-p", TOP_PORTS,
                "--open",              # only report open ports
                "-oX", "-",            # XML output to stdout
                ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            print("[portscan] nmap not found — install it (sudo apt install nmap)")
            return []
        except Exception as e:
            print(f"[portscan] {ip} failed: {e}")
            return []

    return parse_nmap_xml(stdout.decode(errors="ignore"), ip)


def parse_nmap_xml(xml_text: str, ip: str) -> list[dict]:
    """Extract open ports + service/version from nmap XML."""
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid"))
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            if service_el is not None:
                service = service_el.get("name")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                version_str = f"{product} {version}".strip() or None
            else:
                service = None
                version_str = None
            results.append({
                "ip": ip, "port": portid, "protocol": protocol,
                "service": service, "version": version_str,
            })
    return results


async def run_port_scan(scan_id: int, concurrency: int = 5) -> None:
    """Scan unique resolved IPs. Low concurrency — this is intrusive."""
    ips = db.get_unique_resolved_ips(scan_id)
    if not ips:
        print("[portscan] No resolved IPs — run DNS resolution first")
        return

    print(f"[portscan] Scanning {len(ips)} unique IPs, top {len(TOP_PORTS.split(','))} ports "
          f"(concurrency={concurrency})...")
    print("[portscan] Reminder: only scan IPs you're authorized to test.")

    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_ip(ip, sem) for ip in ips]
    all_results = await asyncio.gather(*tasks)

    total_ports = 0
    for ip_results in all_results:
        for svc in ip_results:
            db.insert_service(scan_id, svc["ip"], svc["port"],
                              svc["protocol"], svc["service"], svc["version"])
            total_ports += 1

    print(f"[portscan] Done: {total_ports} open ports across {len(ips)} IPs")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m asm.modules.port_scan <scan_id>")
        sys.exit(1)
    asyncio.run(run_port_scan(int(sys.argv[1])))
