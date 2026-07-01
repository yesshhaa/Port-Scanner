# 🔍 Async TCP Port Scanner

> A Python-based asynchronous TCP port scanner with banner grabbing, service detection, risk classification, and **MITRE ATT&CK T1046** mapping.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1046-red?style=flat)


---

## 📌 What it does

Most port scanners in portfolios are simple socket loops — one port at a time, slow, no context.

This one is different:

- **Async concurrency** — uses `asyncio` to scan hundreds of ports simultaneously instead of one by one
- **Banner grabbing** — reads the service greeting string (e.g. `SSH-2.0-OpenSSH_8.9p1`) to identify exact software versions
- **Risk classification** — labels each open port as CRITICAL / HIGH / MEDIUM / LOW based on known threat exposure
- **CVE hints** — pre-seeded CVE references for high-risk services like SMB, RDP, Telnet, FTP
- **MITRE ATT&CK mapping** — every scan generates a T1046 threat context report
- **JSON + CSV export** — structured output ready for SIEM ingestion or further analysis

---

## 🚀 Quick Start

```bash
# clone the repo
git clone https://github.com/yesshhaa/port-scanner
cd port-scanner

# create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
source venv/bin/activate           # Mac/Linux

# optional: colored terminal output
pip install rich

# run it
python scanner.py localhost
```

---

##  Usage

```bash
# scan common ports (default)
python scanner.py <target>

# scan a port range
python scanner.py <target> -p 1-1024

# scan specific ports
python scanner.py <target> -p 22,80,443,3306,3389

# faster scan, skip banner grabbing
python scanner.py <target> -p 1-1024 -t 0.3 --no-banners

# custom output directory
python scanner.py <target> -o ./reports
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `host` | required | Target IP or hostname |
| `-p, --ports` | `common` | Port range: `1-1024`, `22,80,443`, or `common` |
| `-c, --concurrency` | `300` | Max concurrent connections |
| `-t, --timeout` | `1.0` | Connection timeout in seconds |
| `--no-banners` | off | Skip banner grabbing (faster) |
| `-o, --output` | `outputs/` | Directory to save reports |

---

##  Sample Output

```
╔══════════════════════════════════════════╗
║   ASYNC TCP PORT SCANNER  |  T1046       ║
║   github.com/yesshhaa                    ║
╚══════════════════════════════════════════╝

[*] Scanning 192.168.56.101 — 23 ports | concurrency=300
[+] Scan complete in 1.43s | 6 open port(s) found
[+] JSON report saved → outputs/scan_192_168_56_101_20260623.json
[+] CSV report saved  → outputs/scan_192_168_56_101_20260623.csv

══════════════════════════════════════════════════════
  MITRE ATT&CK CONTEXT
  Technique : T1046 — Network Service Discovery
  Tactic    : Discovery
  Reference : https://attack.mitre.org/techniques/T1046/
══════════════════════════════════════════════════════

  PORT     SERVICE      RISK       CVE HINTS
  --------------------------------------------------
  23       telnet       CRITICAL   CVE-2020-10188
  445      smb          CRITICAL   CVE-2017-0144, CVE-2020-0796
  21       ftp          HIGH       CVE-2010-2075, CVE-2011-2523
  3306     mysql        HIGH       CVE-2012-2122
  22       ssh          MEDIUM     CVE-2023-38408
  80       http         MEDIUM     —
```

---

## 📁 Project Structure

```
port-scanner/
├── scanner.py        # core async scanner + CLI entrypoint
├── services.py       # port → service name, risk level, CVE hints
├── report.py         # JSON/CSV export + MITRE ATT&CK report
└── requirements.txt  # rich (optional)
```

---

## 🎯 MITRE ATT&CK — T1046

| Field | Value |
|-------|-------|
| **Technique ID** | T1046 |
| **Name** | Network Service Discovery |
| **Tactic** | Discovery (TA0007) |
| **Reference** | [attack.mitre.org/techniques/T1046](https://attack.mitre.org/techniques/T1046/) |

Adversaries scan for open ports and running services before lateral movement or exploitation. This tool replicates that behavior in a controlled environment for educational and defensive research purposes.

**Detection:** Alert on SYN sweeps — one source hitting 20+ unique destination ports within 60 seconds. IDS tools like Snort and Suricata have built-in signatures for this pattern.

---

## 🧰 Tech Stack

- **Python 3.10+** — stdlib only (`asyncio`, `socket`, `json`, `csv`, `argparse`, `datetime`)
- **rich** *(optional)* — colored terminal output

No external dependencies required to run the core scanner.

---


This tool is for **educational purposes and authorized security testing only.**
Only scan hosts you own or have explicit written permission to test.
Unauthorized port scanning may violate the CFAA and equivalent laws in your country.

