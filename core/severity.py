# =====================================================
# SENSITIVE SUBDOMAIN KEYWORDS
# =====================================================

SENSITIVE_KEYWORDS = [
    "admin",
    "login",
    "portal",
    "dashboard",
    "cpanel",
    "manage",
    "secure",
    "auth",
    "vpn",
    "internal",
    "staff",
    "api"
]


# =====================================================
# SEVERITY NORMALIZER
# =====================================================

VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def normalize_severity(sev: str) -> str:
    if not sev:
        return "LOW"

    sev = sev.upper()

    if sev not in VALID_SEVERITIES:
        return "MEDIUM"

    return sev


# =====================================================
# SUBDOMAIN CLASSIFICATION
# =====================================================

def classify_subdomain(subdomain: str) -> str:
    """
    Classify sensitivity of newly discovered subdomain
    """

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in subdomain.lower():
            return "HIGH"

    return "MEDIUM"


def severity_for_subdomain_changes(added, removed):
    """
    Generate severity events for subdomain additions/removals
    """

    results = []

    for sub in added:
        sev = normalize_severity(classify_subdomain(sub))
        results.append({
            "type": "new_subdomain",
            "value": sub,
            "severity": sev,
            "source": "osint"
        })

    for sub in removed:
        results.append({
            "type": "removed_subdomain",
            "value": sub,
            "severity": "MEDIUM",
            "source": "osint"
        })

    return results


# =====================================================
# PAGE CHANGE SEVERITY
# =====================================================

def severity_for_page_changes(change_report):
    """
    Generate severity events for page content & link changes
    """

    events = []

    change_pct = change_report.get("text_change_percent", 0)

    # Content change severity
    if change_pct >= 10:
        sev = "HIGH"
    elif change_pct >= 2:
        sev = "MEDIUM"
    elif change_pct > 0:
        sev = "LOW"
    else:
        sev = None

    if sev:
        events.append({
            "type": "content_change",
            "value": f"{change_pct}%",
            "severity": sev,
            "source": "monitoring"
        })

    # New links
    for link in change_report.get("new_links", []):
        sev = "HIGH" if link.startswith("http") else "MEDIUM"

        events.append({
            "type": "new_link",
            "value": link,
            "severity": sev,
            "source": "monitoring"
        })

    # Removed links
    for link in change_report.get("removed_links", []):
        events.append({
            "type": "removed_link",
            "value": link,
            "severity": "LOW",
            "source": "monitoring"
        })

    return events


# =====================================================
# WAPITI SEVERITY INTEGRATION
# =====================================================

def severity_for_wapiti(wapiti_findings):
    """
    Convert Wapiti vulnerability results into severity events
    """

    events = []

    if not wapiti_findings:
        return events

    for vuln in wapiti_findings:

        severity = normalize_severity(vuln.get("severity"))

        events.append({
            "type": "wapiti_vulnerability",
            "value": vuln.get("name"),
            "severity": severity,
            "url": vuln.get("url"),
            "parameter": vuln.get("parameter"),
            "source": "wapiti"
        })

    return events


# =====================================================
# VIRUSTOTAL SEVERITY INTEGRATION
# =====================================================

def severity_for_virustotal(vt_scan_output):
    """
    Convert VirusTotal scan output into severity events
    """

    events = []

    if not vt_scan_output:
        return events

    results = vt_scan_output.get("results", [])

    for r in results:
        domain = r.get("domain")
        malicious = r.get("malicious", 0)
        suspicious = r.get("suspicious", 0)

        # CRITICAL → malicious detections
        if malicious > 0:
            events.append({
                "type": "virustotal_malicious_domain",
                "value": domain,
                "severity": "CRITICAL",
                "detections": malicious,
                "source": "virustotal"
            })

        # HIGH → suspicious detections
        elif suspicious > 0:
            events.append({
                "type": "virustotal_suspicious_domain",
                "value": domain,
                "severity": "HIGH",
                "detections": suspicious,
                "source": "virustotal"
            })

    return events


# =====================================================
# MERGED SEVERITY PIPELINE
# =====================================================

def build_severity_events(
    added_subdomains,
    removed_subdomains,
    change_report,
    wapiti_findings=None,
    vt_results=None
):
    """
    Central severity builder used by orchestrator
    """

    events = []

    events.extend(severity_for_subdomain_changes(added_subdomains, removed_subdomains))

    if change_report:
        events.extend(severity_for_page_changes(change_report))

    if wapiti_findings:
        events.extend(severity_for_wapiti(wapiti_findings))

    if vt_results:
        events.extend(severity_for_virustotal(vt_results))

    return events
