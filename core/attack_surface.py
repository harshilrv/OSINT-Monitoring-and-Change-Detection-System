from collections import defaultdict
from typing import List, Dict
from core.models import Finding


# =========================================================
# GROUP BY IP
# =========================================================

def map_by_ip(findings: List[Finding]) -> Dict[str, List[str]]:
    infra = defaultdict(list)

    for f in findings:
        ip = f.metadata.get("ip")
        if ip:
            infra[ip].append(f.value)

    return dict(infra)


# =========================================================
# GROUP BY SERVER TYPE
# =========================================================

def map_by_server(findings: List[Finding]) -> Dict[str, List[str]]:
    servers = defaultdict(list)

    for f in findings:
        http = f.metadata.get("http", {})
        server = http.get("server")

        if server:
            servers[server].append(f.value)

    return dict(servers)


# =========================================================
# HIGH RISK ASSET DETECTION
# =========================================================

RISK_WORDS = [
    "admin",
    "login",
    "dev",
    "test",
    "stage",
    "vpn",
    "internal",
    "gateway",
    "db"
]


def find_high_risk_assets(findings: List[Finding]) -> List[str]:
    risky = []

    for f in findings:
        name = f.value.lower()

        if any(word in name for word in RISK_WORDS):
            risky.append(name)

    return sorted(risky)


# =========================================================
# MAIN MAPPER
# =========================================================

def build_attack_surface(findings: List[Finding]) -> dict:

    return {
        "ip_map": map_by_ip(findings),
        "server_map": map_by_server(findings),
        "high_risk_assets": find_high_risk_assets(findings),
        "total_assets": len(findings)
    }


# =========================================================
# PRINT REPORT
# =========================================================

def print_attack_surface(report: dict):

    print("\n========= ATTACK SURFACE MAP =========\n")

    print("Total Assets:", report["total_assets"])
    print()

    # ---------------- IP MAP ----------------
    print("INFRASTRUCTURE GROUPING (BY IP)\n")

    if not report["ip_map"]:
        print("No IP mapping available\n")
    else:
        for ip, hosts in report["ip_map"].items():
            print(ip)
            for h in hosts:
                print("  ├─", h)
            print()

    # ---------------- SERVER MAP ----------------
    print("TECH STACK DISTRIBUTION\n")

    if not report["server_map"]:
        print("No server fingerprinting data\n")
    else:
        for server, hosts in report["server_map"].items():
            print(server)
            for h in hosts:
                print("  ├─", h)
            print()

    # ---------------- HIGH RISK ----------------
    print("HIGH RISK ASSETS\n")

    if not report["high_risk_assets"]:
        print("None detected")
    else:
        for asset in report["high_risk_assets"]:
            print("  ⚠", asset)

    print("\n======================================\n")
