import subprocess
import json
import os
from pathlib import Path
from datetime import datetime

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter


REPORT_DIR = Path("reports/wapiti")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


class WapitiScanner:
    """
    Wapiti Web Vulnerability Scanner Integration
    Handles vulnerability scanning and PDF report generation
    """

    def __init__(self):
        self.report_dir = REPORT_DIR
        self.last_pdf_path = None
        self.last_json_path = None

    # =============================
    # REPORT PATHS
    # =============================

    def _generate_report_paths(self, target):
        safe = target.replace("https://", "").replace("http://", "").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.report_dir / f"{safe}_{timestamp}.json"
        pdf_path = self.report_dir / f"{safe}_report_{timestamp}.pdf"
        return json_path, pdf_path

    # =============================
    # RUN WAPITI
    # =============================

    def run_scan(self, target_url, mode="passive", scope="domain", depth=2):

        json_path, pdf_path = self._generate_report_paths(target_url)

        command = [
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", str(json_path),
            "--scope", scope,
            "-d", str(depth),
            "--flush-session",
            "--flush-attacks"
        ]

        if mode == "active":
            command.extend(["-m", "all"])

        try:
            print(f"\n[*] Running Wapiti scan on {target_url}...")

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore",
                env=env
            )

            if result.returncode != 0:
                print("[!] Wapiti returned errors but continuing...")
                print(result.stderr[:400])

            print("[+] Scan completed")

        except FileNotFoundError:
            print("[!] Wapiti not installed. Install using:")
            print("    pip install wapiti3")
            return []

        except Exception as e:
            print("[!] Wapiti execution failed:", e)
            return []

        # =============================
        # LOAD JSON REPORT
        # =============================

        if not json_path.exists():
            print("[!] Wapiti report not generated.")
            return []

        try:
            data = self._load_report(json_path)
        except Exception as e:
            print("[!] Failed loading Wapiti report:", e)
            return []

        findings = self.parse_vulnerabilities(data)

        if not findings:
            print("[*] No vulnerabilities found")
            score, classification = 0, "LOW"
        else:
            score, classification = self.calculate_score(findings)

        # =============================
        # GENERATE PDF
        # =============================

        try:
            self.generate_pdf(findings, score, classification, pdf_path, target_url)

            # 🔥 CRITICAL FIX — expose PDF to orchestrator/email
            self.last_pdf_path = str(pdf_path)
            self.last_json_path = str(json_path)

            print(f"[+] PDF report generated: {pdf_path}")

        except Exception as e:
            print("[!] PDF generation failed:", e)

        print(f"\nVulnerability Score: {score}/100")
        print(f"Risk Level: {classification}\n")

        return findings

    # =============================
    # LOAD REPORT
    # =============================

    def _load_report(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)

    # =============================
    # PARSE VULNERABILITIES
    # =============================

    def parse_vulnerabilities(self, data):

        findings = []

        for category, entries in data.get("vulnerabilities", {}).items():
            for item in entries:
                findings.append({
                    "name": category,
                    "description": item.get("info", "No description"),
                    "severity": self.map_severity(item.get("level", 0)),
                    "url": item.get("path", "N/A"),
                    "module": item.get("module", "N/A"),
                    "parameter": item.get("parameter", "N/A")
                })

        return findings

    # =============================
    # SEVERITY MAPPING
    # =============================

    def map_severity(self, level):
        return {
            3: "Critical",
            2: "High",
            1: "Medium",
            0: "Low"
        }.get(level, "Low")

    # =============================
    # SCORE ENGINE
    # =============================

    def calculate_score(self, findings):

        weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 1
        }

        total = sum(weights.get(f["severity"], 0) for f in findings)
        score = min(100, total)

        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level

    # =============================
    # PDF GENERATION
    # =============================

    def generate_pdf(self, findings, score, classification, pdf_path, target_url):

        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("Web Vulnerability Assessment Report", styles["Title"]))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph(f"<b>Target:</b> {target_url}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(f"<b>Score:</b> {score}/100", styles["Heading2"]))
        elements.append(Paragraph(f"<b>Risk:</b> {classification}", styles["Heading2"]))
        elements.append(Paragraph(f"<b>Total Issues:</b> {len(findings)}", styles["Heading2"]))
        elements.append(Spacer(1, 20))

        severity_counts = {}
        for f in findings:
            severity_counts[f['severity']] = severity_counts.get(f['severity'], 0) + 1

        elements.append(Paragraph("<b>Severity Breakdown:</b>", styles["Heading3"]))
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = severity_counts.get(sev, 0)
            if count:
                elements.append(Paragraph(f"{sev}: {count}", styles["Normal"]))

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("<b>Findings:</b>", styles["Heading2"]))

        for i, f in enumerate(findings, 1):
            elements.append(Paragraph(f"{i}. {f['name']}", styles["Heading3"]))
            elements.append(Paragraph(f"Severity: {f['severity']}", styles["Normal"]))
            elements.append(Paragraph(f"URL: {f['url']}", styles["Normal"]))
            elements.append(Paragraph(f"Module: {f['module']}", styles["Normal"]))
            elements.append(Paragraph(f"Description: {f['description'][:400]}", styles["Normal"]))
            elements.append(Spacer(1, 12))

        doc.build(elements)
