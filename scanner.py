"""
Async TCP Port Scanner
MITRE ATT&CK T1046 — Network Service Discovery
Author: Yesha Shah | github.com/yesshhaa
"""

import asyncio
import socket
import argparse
import datetime
import os
from services import SERVICE_MAP, get_risk_level
from report import export_results, print_mitre_report

BANNER = """
╔══════════════════════════════════════════╗
║   ASYNC TCP PORT SCANNER  |  T1046       ║
║   github.com/yesshhaa                    ║
╚══════════════════════════════════════════╝
"""

# ── BANNER GRABBER ──────────────────────────────────

async def grab_banner(reader, timeout: float = 2.0) -> str:
    """Read up to 1024 bytes from an open connection."""
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, Exception):
        return ""

# ── SINGLE PORT SCAN ────────────────────────────────

async def scan_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 1.0,
    grab_banners: bool = True
) -> dict | None:
    """
    Attempt a TCP connection to host:port.
    Returns a result dict if open, None if closed/filtered.
    """
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            banner = ""
            if grab_banners:
                banner = await grab_banner(reader)

            writer.close()
            await writer.wait_closed()

            service = SERVICE_MAP.get(port, {})
            service_name = service.get("name")
            if not service_name:
                try:
                    service_name = socket.getservbyport(port)
                except OSError:
                    service_name = "unknown"

            return {
                "port": port,
                "state": "open",
                "service": service_name,
                "banner": banner,
                "risk": get_risk_level(port),
                "cve_hints": service.get("cve_hints", []),
                "protocol": "tcp",
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

# ── BATCH SCAN ──────────────────────────────────────

async def run_scan(
    host: str,
    ports: list[int],
    concurrency: int = 300,
    timeout: float = 1.0,
    grab_banners: bool = True
) -> list[dict]:
    """Scan all ports concurrently, respect semaphore limit."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        scan_port(host, port, semaphore, timeout, grab_banners)
        for port in ports
    ]

    print(f"\n[*] Scanning {host} — {len(ports)} ports | concurrency={concurrency}")
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r is not None]
    return sorted(open_ports, key=lambda x: x["port"])

# ── PORT RANGE PARSER ───────────────────────────────

def parse_ports(port_arg: str) -> list[int]:
    """
    Parse port argument into a list of ints.
    Supports: '80', '22,80,443', '1-1024', 'common'
    """
    if port_arg == "common":
        return list(SERVICE_MAP.keys())
    if "-" in port_arg and "," not in port_arg:
        start, end = port_arg.split("-")
        return list(range(int(start), int(end) + 1))
    return [int(p.strip()) for p in port_arg.split(",")]

# ── ENTRYPOINT ──────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Async TCP Port Scanner with MITRE ATT&CK T1046 mapping"
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Port range: '1-1024', '22,80,443', 'common' (default)"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=300,
        help="Max concurrent connections (default: 300)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Skip banner grabbing (faster)"
    )
    parser.add_argument(
        "-o", "--output",
        default="outputs",
        help="Output directory (default: outputs/)"
    )

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    os.makedirs(args.output, exist_ok=True)

    start_time = datetime.datetime.now()
    open_ports = asyncio.run(
        run_scan(
            host=args.host,
            ports=ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            grab_banners=not args.no_banners
        )
    )
    elapsed = (datetime.datetime.now() - start_time).total_seconds()

    print(f"\n[+] Scan complete in {elapsed:.2f}s | {len(open_ports)} open port(s) found")

    if open_ports:
        export_results(args.host, open_ports, args.output, start_time)
        print_mitre_report(open_ports)
    else:
        print("[-] No open ports found.")

if __name__ == "__main__":
    main()