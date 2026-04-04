from dotenv import load_dotenv
load_dotenv()

import smtplib
from email.message import EmailMessage
import os
from datetime import datetime
import csv
from pathlib import Path


# ----------------------------------
# SMTP CONFIG
# ----------------------------------

SMTP_SERVER = os.getenv("OSINT_SMTP_SERVER")
SMTP_PORT = int(os.getenv("OSINT_SMTP_PORT", "587"))
SMTP_USER = os.getenv("OSINT_SMTP_USER")
SMTP_PASSWORD = os.getenv("OSINT_SMTP_PASSWORD")

ALERT_SENDER = os.getenv("OSINT_ALERT_SENDER")
ALERT_RECIPIENTS = os.getenv("OSINT_ALERT_RECIPIENTS", "")

REPORT_DIR = Path("reports/daily")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------
# EMAIL CORE
# ----------------------------------

def send_email(subject: str, body: str, attachments=None):

    if not all([
        SMTP_SERVER,
        SMTP_USER,
        SMTP_PASSWORD,
        ALERT_SENDER,
        ALERT_RECIPIENTS
    ]):
        print("[!] Email not configured")
        return

    msg = EmailMessage()
    msg["From"] = ALERT_SENDER
    msg["To"] = ALERT_RECIPIENTS
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach files
    if attachments:
        for file_path in attachments:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "rb") as f:
                        msg.add_attachment(
                            f.read(),
                            maintype="application",
                            subtype="octet-stream",
                            filename=os.path.basename(file_path)
                        )
                except Exception as e:
                    print("[!] Attachment failed:", e)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print("[✓] Email sent successfully")

    except Exception as e:
        print("[!] Failed to send email:", e)


# ----------------------------------
# CSV REPORT GENERATOR
# ----------------------------------

def generate_daily_csv(
    target,
    findings,
    change_report,
    trend_metrics,
    vt_results,
    wapiti_findings,
    alerts
):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"{target}_daily_report_{timestamp}.csv"

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["OSINT DAILY REPORT"])
        writer.writerow(["Target", target])
        writer.writerow(["Generated", datetime.now()])
        writer.writerow([])

        # SUBDOMAINS
        writer.writerow(["SUBDOMAINS"])
        writer.writerow(["Subdomain"])
        for f in findings:
            writer.writerow([f.value])
        writer.writerow([])

        # WEBSITE CHANGES
        writer.writerow(["WEBSITE CHANGES"])
        writer.writerow(["Text Change %", change_report.get("text_change_percent", 0)])
        writer.writerow(["New Links", len(change_report.get("new_links", []))])
        writer.writerow(["Removed Links", len(change_report.get("removed_links", []))])
        writer.writerow([])

        # TREND
        writer.writerow(["TREND"])
        writer.writerow(["Volatility", trend_metrics.get("subdomain_volatility")])
        writer.writerow([])

        # VIRUSTOTAL
        if vt_results:
            stats = vt_results.get("statistics", {})
            writer.writerow(["VIRUSTOTAL SUMMARY"])
            writer.writerow(["Total", stats.get("total_targets", 0)])
            writer.writerow(["Malicious", stats.get("malicious", 0)])
            writer.writerow(["Suspicious", stats.get("suspicious", 0)])
            writer.writerow([])

        # WAPITI
        if wapiti_findings:
            writer.writerow(["WAPITI VULNERABILITIES"])
            writer.writerow(["Vulnerability", "Severity", "URL"])

            for v in wapiti_findings:
                writer.writerow([
                    v.get("name"),
                    v.get("severity"),
                    v.get("url")
                ])
            writer.writerow([])

        # ALERTS
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


# ----------------------------------
# DAILY SUMMARY EMAIL (CSV + PDF)
# ----------------------------------

def send_daily_summary(
    target,
    findings,
    change_report,
    trend_metrics,
    vt_results,
    wapiti_findings,
    alerts,
    wapiti_pdf=None   # 🔥 THIS FIXES YOUR ERROR
):

    csv_file = generate_daily_csv(
        target,
        findings,
        change_report,
        trend_metrics,
        vt_results,
        wapiti_findings,
        alerts
    )

    subject = f"[OSINT REPORT] {target} — {datetime.now().strftime('%Y-%m-%d')}"

    body = """
OSINT Security Monitoring Report

Attached:
• Daily CSV intelligence report
• Wapiti vulnerability assessment PDF

Alerts triggered if any HIGH/CRITICAL issues found.
"""

    attachments = [csv_file]

    # attach wapiti pdf
    if wapiti_pdf:
        attachments.append(wapiti_pdf)

    send_email(subject, body, attachments)


# ----------------------------------
# ALERT EMAIL (DISABLED — MERGED INTO SUMMARY)
# ----------------------------------

def notify_alerts(target, alerts):
    """
    Disabled — alerts now go inside main report mail
    """
    return
from dotenv import load_dotenv
load_dotenv()

import smtplib
from email.message import EmailMessage
import os
from datetime import datetime
import csv
from pathlib import Path


# ----------------------------------
# SMTP CONFIG
# ----------------------------------

SMTP_SERVER = os.getenv("OSINT_SMTP_SERVER")
SMTP_PORT = int(os.getenv("OSINT_SMTP_PORT", "587"))
SMTP_USER = os.getenv("OSINT_SMTP_USER")
SMTP_PASSWORD = os.getenv("OSINT_SMTP_PASSWORD")

ALERT_SENDER = os.getenv("OSINT_ALERT_SENDER")
ALERT_RECIPIENTS = os.getenv("OSINT_ALERT_RECIPIENTS", "")

REPORT_DIR = Path("reports/daily")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------
# EMAIL CORE
# ----------------------------------

def send_email(subject: str, body: str, attachments=None):

    if not all([
        SMTP_SERVER,
        SMTP_USER,
        SMTP_PASSWORD,
        ALERT_SENDER,
        ALERT_RECIPIENTS
    ]):
        print("[!] Email not configured")
        return

    msg = EmailMessage()
    msg["From"] = ALERT_SENDER
    msg["To"] = ALERT_RECIPIENTS
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach files
    if attachments:
        for file_path in attachments:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "rb") as f:
                        msg.add_attachment(
                            f.read(),
                            maintype="application",
                            subtype="octet-stream",
                            filename=os.path.basename(file_path)
                        )
                except Exception as e:
                    print("[!] Attachment failed:", e)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print("[✓] Email sent successfully")

    except Exception as e:
        print("[!] Failed to send email:", e)


# ----------------------------------
# CSV REPORT GENERATOR
# ----------------------------------

def generate_daily_csv(
    target,
    findings,
    change_report,
    trend_metrics,
    vt_results,
    wapiti_findings,
    alerts
):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"{target}_daily_report_{timestamp}.csv"

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # ======================================================
        # HEADER
        # ======================================================
        writer.writerow(["OSINT DAILY REPORT"])
        writer.writerow(["Target", target])
        writer.writerow(["Generated", datetime.now()])
        writer.writerow([])

        # ======================================================
        # CURRENT FINDINGS (TABULAR)
        # ======================================================
        writer.writerow(["CURRENT FINDINGS"])
        writer.writerow([
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
            http = f.metadata.get("http", {}) if hasattr(f, "metadata") else {}
            writer.writerow([
                f.value,
                f.metadata.get("ip", ""),
                http.get("alive", ""),
                http.get("status", ""),
                http.get("title", ""),
                http.get("server", ""),
                http.get("content_type", ""),
                f.confidence
            ])

        writer.writerow([])

        # ======================================================
        # WEBSITE CHANGES
        # ======================================================
        writer.writerow(["WEBSITE CHANGES"])
        writer.writerow(["Text Change %", change_report.get("text_change_percent", 0)])
        writer.writerow(["New Links", len(change_report.get("new_links", []))])
        writer.writerow(["Removed Links", len(change_report.get("removed_links", []))])
        writer.writerow([])

        # ======================================================
        # TREND
        # ======================================================
        writer.writerow(["TREND"])
        writer.writerow(["Volatility", trend_metrics.get("subdomain_volatility")])
        writer.writerow([])

        # ======================================================
        # VIRUSTOTAL
        # ======================================================
        writer.writerow(["VIRUSTOTAL SUMMARY"])
        if vt_results:
            stats = vt_results.get("statistics", {})
            writer.writerow(["Total", stats.get("total_targets", 0)])
            writer.writerow(["Malicious", stats.get("malicious", 0)])
            writer.writerow(["Suspicious", stats.get("suspicious", 0)])
        else:
            writer.writerow(["Total", 0])
            writer.writerow(["Malicious", 0])
            writer.writerow(["Suspicious", 0])

        writer.writerow([])

        # ======================================================
        # WAPITI
        # ======================================================
        writer.writerow(["WAPITI VULNERABILITIES"])
        writer.writerow(["Vulnerability", "Severity", "URL", "Module"])

        for v in wapiti_findings or []:
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


# ----------------------------------
# DAILY SUMMARY EMAIL (CSV + PDF)
# ----------------------------------

def send_daily_summary(
    target,
    findings,
    change_report,
    trend_metrics,
    vt_results,
    wapiti_findings,
    alerts,
    wapiti_pdf=None
):

    csv_file = generate_daily_csv(
        target,
        findings,
        change_report,
        trend_metrics,
        vt_results,
        wapiti_findings,
        alerts
    )

    subject = f"[OSINT REPORT] {target} — {datetime.now().strftime('%Y-%m-%d')}"

    body = """
OSINT Security Monitoring Report

Attached:
• Daily CSV intelligence report
• Wapiti vulnerability assessment PDF (if scan enabled)

Alerts triggered automatically if:
- High/Critical vulnerabilities found
- Malicious/suspicious domains detected
"""

    attachments = [csv_file]

    if wapiti_pdf and os.path.exists(wapiti_pdf):
        attachments.append(wapiti_pdf)

    send_email(subject, body, attachments)


# ----------------------------------
# ALERT MAIL DISABLED
# ----------------------------------

def notify_alerts(target, alerts):
    """
    Alerts merged into main summary mail
    """
    return
