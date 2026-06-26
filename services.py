"""
Common port → service mappings with risk levels and CVE hints.
Expand this as you add more threat intelligence context.
"""

SERVICE_MAP: dict[int, dict] = {
    21:  {"name": "ftp",      "risk": "HIGH",   "cve_hints": ["CVE-2010-2075", "CVE-2011-2523"]},
    22:  {"name": "ssh",      "risk": "MEDIUM", "cve_hints": ["CVE-2023-38408"]},
    23:  {"name": "telnet",   "risk": "CRITICAL","cve_hints": ["CVE-2020-10188"]},
    25:  {"name": "smtp",     "risk": "MEDIUM", "cve_hints": []},
    53:  {"name": "dns",      "risk": "MEDIUM", "cve_hints": ["CVE-2020-1350"]},
    80:  {"name": "http",     "risk": "MEDIUM", "cve_hints": []},
    110: {"name": "pop3",     "risk": "MEDIUM", "cve_hints": []},
    135: {"name": "msrpc",    "risk": "HIGH",   "cve_hints": ["CVE-2003-0352"]},
    139: {"name": "netbios",  "risk": "HIGH",   "cve_hints": ["CVE-2017-0144"]},
    143: {"name": "imap",     "risk": "MEDIUM", "cve_hints": []},
    443: {"name": "https",    "risk": "LOW",    "cve_hints": []},
    445: {"name": "smb",      "risk": "CRITICAL","cve_hints": ["CVE-2017-0144", "CVE-2020-0796"]},
    512: {"name": "rexec",    "risk": "CRITICAL","cve_hints": []},
    513: {"name": "rlogin",   "risk": "CRITICAL","cve_hints": []},
    514: {"name": "rsh",      "risk": "CRITICAL","cve_hints": []},
    1433:{"name": "mssql",    "risk": "HIGH",   "cve_hints": []},
    3306:{"name": "mysql",    "risk": "HIGH",   "cve_hints": ["CVE-2012-2122"]},
    3389:{"name": "rdp",      "risk": "CRITICAL","cve_hints": ["CVE-2019-0708"]},
    5900:{"name": "vnc",      "risk": "HIGH",   "cve_hints": []},
    6379:{"name": "redis",    "risk": "HIGH",   "cve_hints": ["CVE-2022-0543"]},
    8080:{"name": "http-alt", "risk": "MEDIUM", "cve_hints": []},
    8443:{"name": "https-alt","risk": "LOW",    "cve_hints": []},
    27017:{"name":"mongodb",  "risk": "HIGH",   "cve_hints": []},
}

RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def get_risk_level(port: int) -> str:
    return SERVICE_MAP.get(port, {}).get("risk", "INFO")