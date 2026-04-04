from typing import List, Dict


# ==========================================================
# MAIN ALERT ENGINE (SUBDOMAIN + PAGE + TREND)
# ==========================================================

def evaluate_alerts(
    added_subdomains: List[str],
    removed_subdomains: List[str],
    page_change_report: Dict,
    trend_metrics: Dict
) -> List[Dict]:

    alerts = []

    # -----------------------
    # Subdomain alerts
    # -----------------------

    if removed_subdomains:
        alerts.append({
            "severity": "CRITICAL",
            "type": "SUBDOMAIN_REMOVED",
            "details": removed_subdomains
        })

    if len(added_subdomains) >= 3:
        alerts.append({
            "severity": "HIGH",
            "type": "SUBDOMAIN_ADDED",
            "details": added_subdomains
        })

    # -----------------------
    # Page content alerts
    # -----------------------

    if not page_change_report.get("baseline"):
        change = page_change_report.get("text_change_percent", 0)

        if change >= 15:
            alerts.append({
                "severity": "HIGH",
                "type": "PAGE_CHANGE",
                "details": f"{change}% text changed"
            })
        elif change >= 5:
            alerts.append({
                "severity": "MEDIUM",
                "type": "PAGE_CHANGE",
                "details": f"{change}% text changed"
            })

    # -----------------------
    # Trend-based alerts
    # -----------------------

    volatility = trend_metrics.get("subdomain_volatility")

    if volatility == "HIGH":
        alerts.append({
            "severity": "HIGH",
            "type": "VOLATILITY_SPIKE",
            "details": "High subdomain churn detected"
        })

    elif volatility == "MEDIUM":
        alerts.append({
            "severity": "MEDIUM",
            "type": "VOLATILITY_INCREASE",
            "details": "Moderate subdomain churn detected"
        })

    return alerts


# ==========================================================
# VIRUSTOTAL ALERT ENGINE
# ==========================================================

def evaluate_vt_alerts(vt_data: Dict) -> List[Dict]:

    alerts = []

    if not vt_data:
        return alerts

    stats = vt_data.get("statistics", {})

    # 🔥 FIX: correct VT keys
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)

    if malicious_count > 0:
        alerts.append({
            "severity": "CRITICAL",
            "type": "VT_MALICIOUS_DOMAIN",
            "details": f"{malicious_count} malicious domains detected"
        })

    if suspicious_count > 0:
        alerts.append({
            "severity": "HIGH",
            "type": "VT_SUSPICIOUS_DOMAIN",
            "details": f"{suspicious_count} suspicious domains detected"
        })

    return alerts


# ==========================================================
# WAPITI ALERT ENGINE (HIGH + CRITICAL TRIGGER)
# ==========================================================

def evaluate_wapiti_alerts(wapiti_findings: List[Dict]) -> List[Dict]:

    alerts = []

    if not wapiti_findings:
        return alerts

    critical = [f for f in wapiti_findings if f.get("severity") == "Critical"]
    high = [f for f in wapiti_findings if f.get("severity") == "High"]

    if critical:
        alerts.append({
            "severity": "CRITICAL",
            "type": "WAPITI_CRITICAL_VULNERABILITY",
            "details": f"{len(critical)} critical vulnerabilities found"
        })

    if high:
        alerts.append({
            "severity": "HIGH",
            "type": "WAPITI_HIGH_VULNERABILITY",
            "details": f"{len(high)} high vulnerabilities found"
        })

    return alerts


# ==========================================================
# MASTER ALERT MERGER (USED BY ORCHESTRATOR)
# ==========================================================

def merge_all_alerts(
    base_alerts: List[Dict],
    vt_alerts: List[Dict],
    wapiti_alerts: List[Dict]
) -> List[Dict]:
    """
    Combine all alert sources into one final alert list
    """
    return base_alerts + vt_alerts + wapiti_alerts


# ==========================================================
# PRINT ALERTS
# ==========================================================

def print_alerts(alerts: List[Dict]):

    if not alerts:
        print("\n[✓] No alerts triggered\n")
        return

    print("\n========= ALERTS =========\n")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']} → {alert['details']}")

    print("\n==========================\n")
