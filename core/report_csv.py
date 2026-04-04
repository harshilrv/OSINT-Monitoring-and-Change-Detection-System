import csv
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports/daily")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_daily_csv(
    target,
    findings,          # full Finding objects (CURRENT FINDINGS)
    subdomains,        # simple list
    change_report,
    vt_results,
    wapiti_findings,
    alerts
):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"{target}_daily_{timestamp}.csv"

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # ======================================================
        # HEADER
        # ======================================================
        writer.writerow(["OSINT DAILY REPORT"])
        writer.writerow(["Target", target])
        writer.writerow(["Generated", datetime.now()])
        writer.writerow([])

        # ======================================================
        # CURRENT FINDINGS TABLE (FULL TECH DATA)
        # ======================================================
        writer.writerow(["CURRENT FINDINGS"])
        writer.writerow([
            "Type",
            "Subdomain",
            "IP",
            "Alive",
            "HTTP Status",
            "Title",
            "Server",
            "Content-Type",
            "Confidence"
        ])

        for f in findings:
            http_meta = f.metadata.get("http", {}) if f.metadata else {}

            writer.writerow([
                f.type,
                f.value,
                f.metadata.get("ip", "N/A"),
                http_meta.get("alive", "N/A"),
                http_meta.get("status", "N/A"),
                http_meta.get("title", "N/A"),
                http_meta.get("server", "N/A"),
                http_meta.get("content_type", "N/A"),
                f.confidence
            ])

        writer.writerow([])

        # ======================================================
        # SUBDOMAIN LIST
        # ======================================================
        writer.writerow(["SUBDOMAINS"])
        writer.writerow(["Subdomain"])

        for sub in subdomains:
            writer.writerow([sub])

        writer.writerow([])

        # ======================================================
        # PAGE CHANGE
        # ======================================================
        writer.writerow(["WEBSITE CHANGES"])
        writer.writerow(["Text Change %", change_report.get("text_change_percent", 0)])
        writer.writerow(["New Links", len(change_report.get("new_links", []))])
        writer.writerow(["Removed Links", len(change_report.get("removed_links", []))])
        writer.writerow([])

        # ======================================================
        # VIRUSTOTAL RESULTS
        # ======================================================
        writer.writerow(["VIRUSTOTAL RESULTS"])
        writer.writerow(["Domain", "Severity", "Malicious", "Suspicious"])

        malicious_total = 0
        suspicious_total = 0

        if vt_results:
            for r in vt_results.get("results", []):

                sev = "CLEAN"

                if r.get("malicious", 0) > 0:
                    sev = "CRITICAL"
                    malicious_total += 1

                elif r.get("suspicious", 0) > 0:
                    sev = "HIGH"
                    suspicious_total += 1

                writer.writerow([
                    r.get("domain"),
                    sev,
                    r.get("malicious", 0),
                    r.get("suspicious", 0)
                ])

        # write 0 if none found
        if malicious_total == 0 and suspicious_total == 0:
            writer.writerow(["-", "CLEAN", 0, 0])

        writer.writerow([])

        # ======================================================
        # WAPITI VULNERABILITIES
        # ======================================================
        writer.writerow(["WAPITI VULNERABILITIES"])
        writer.writerow(["Vulnerability", "Severity", "URL", "Module"])

        for v in wapiti_findings:
            writer.writerow([
                v.get("name"),
                v.get("severity"),
                v.get("url"),
                v.get("module")
            ])

        writer.writerow([])

        # ======================================================
        # ALERTS
        # ======================================================
        writer.writerow(["ALERTS"])
        writer.writerow(["Severity", "Type", "Details"])

        if alerts:
            for a in alerts:
                writer.writerow([
                    a.get("severity"),
                    a.get("type"),
                    a.get("details")
                ])
        else:
            writer.writerow(["None", "-", "-"])

    return str(csv_path)
