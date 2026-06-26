import json
import csv
import os
import datetime
from services import RISK_ORDER

def export_results(
    host: str,
    results: list[dict],
    output_dir: str,
    timestamp: datetime.datetime
) -> None:
    """Write scan results to JSON and CSV."""
    date_str = timestamp.strftime("%Y%m%d_%H%M%S")
    safe_host = host.replace(".", "_")
    base = os.path.join(output_dir, f"scan_{safe_host}_{date_str}")

    report = {
        "target": host,
        "scan_time": timestamp.isoformat(),
        "mitre_technique": {
            "id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/"
        },
        "open_ports": results,
        "summary": {
            "total_open": len(results),
            "critical": sum(1 for r in results if r["risk"] == "CRITICAL"),
            "high":     sum(1 for r in results if r["risk"] == "HIGH"),
            "medium":   sum(1 for r in results if r["risk"] == "MEDIUM"),
        }
    }

    # JSON export
    json_path = base + ".json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved → {json_path}")

    # CSV export
    csv_path = base + ".csv"
    fields = ["port", "state", "service", "risk", "banner", "cve_hints"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            row_copy = dict(row)
            row_copy["cve_hints"] = "; ".join(row.get("cve_hints", []))
            writer.writerow(row_copy)
    print(f"[+] CSV report saved  → {csv_path}")


def print_mitre_report(results: list[dict]) -> None:
    """Print a formatted MITRE ATT&CK context report to terminal."""
    print("\n" + "═" * 54)
    print("  MITRE ATT&CK CONTEXT")
    print("  Technique : T1046 — Network Service Discovery")
    print("  Tactic    : Discovery")
    print("  Reference : https://attack.mitre.org/techniques/T1046/")
    print("═" * 54 + "\n")
    print("  Adversaries use tools like this to enumerate open")
    print("  services before lateral movement or exploitation.")
    print()
    print(f"  {'PORT':<8} {'SERVICE':<12} {'RISK':<10} {'CVE HINTS'}")
    print("  " + "-" * 50)

    sorted_results = sorted(
        results,
        key=lambda x: RISK_ORDER.get(x["risk"], 0),
        reverse=True
    )

    for r in sorted_results:
        cves = ", ".join(r.get("cve_hints", [])) or "—"
        print(f"  {r['port']:<8} {r['service']:<12} {r['risk']:<10} {cves}")
    print()