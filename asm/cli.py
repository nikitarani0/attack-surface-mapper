import argparse
import asyncio
import sys

from asm import db
from asm.pipeline import run_full_scan
from asm.modules import report as report_mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asm",
        description="Attack Surface Mapper — cloud-focused recon for bug bounty.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # asm scan --domain X [--ports] [--passive]
    p_scan = sub.add_parser("scan", help="Run a full attack-surface scan on a domain")
    p_scan.add_argument("--domain", "-d", required=True,
                        help="Target domain (authorized scope only)")
    p_scan.add_argument("--ports", action="store_true",
                        help="Enable port scanning (intrusive — authorized targets only)")
    p_scan.add_argument("--passive", action="store_true",
                        help="Passive-only: no requests sent to target. "
                             "Compliant with programs that ban automated scanning.")

    # asm report --scan-id N
    p_report = sub.add_parser("report", help="Regenerate reports for an existing scan")
    p_report.add_argument("--scan-id", "-s", type=int, required=True)

    # asm list
    sub.add_parser("list", help="List all past scans")

    return parser


def cmd_list():
    db.init_db()
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT id, target, started_at, status FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()
    if not rows:
        print("No scans yet. Run: asm scan --domain example.com")
        return
    print(f"{'ID':<5} {'TARGET':<30} {'STATUS':<10} STARTED")
    for r in rows:
        print(f"{r['id']:<5} {r['target']:<30} {r['status']:<10} {r['started_at']}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        # --ports is ignored in passive mode (port scanning sends traffic to target)
        if args.passive and args.ports:
            print("[cli] --ports ignored: passive mode sends no traffic to the target.")
        asyncio.run(run_full_scan(
            args.domain,
            skip_ports=not args.ports,
            passive=args.passive,
        ))
    elif args.command == "report":
        report_mod.generate_reports(args.scan_id)
    elif args.command == "list":
        cmd_list()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
