from typing import List
import time
import re

from core.formatters import print_phone_result, print_truecaller_result, print_truecaller_result, print_username_search_result
from core.formatters import print_phone_result
from core.models import Finding
from core.registry import get_modules_for_target
from core.storage import save_findings, load_last_scan
from core.change_detector import detect_changes, print_change_report
from core.correlator import correlate_findings
from core.filters import apply_filters
from core.prioritizer import prioritize_findings
from core.verifier import mark_verified

from core.trends import print_trend_report, calculate_trend_metrics
from core.alerts import (
    evaluate_alerts,
    evaluate_wapiti_alerts,
    evaluate_vt_alerts,
    merge_all_alerts,
    print_alerts
)

from core.severity import build_severity_events
from core.dns_analyzer import enrich_findings_dns
from core.http_probe import enrich_findings_http
from core.notifier import send_daily_summary

# Optional integrations
from modules.wapiti_integrate import WapitiScanner
from modules.vt_integrate import VirusTotalScanner
from core.attack_surface import build_attack_surface, print_attack_surface

from tqdm import tqdm

from core.formatters import (
    print_phone_result,
    print_truecaller_result,
    print_username_result,
    print_email_result,
    print_username_search_result   # ✅ THIS IS IMPORTANT
)

# =====================================================
# TARGET TYPE DETECTION
# =====================================================

def detect_target_type(target: str) -> str:

    if re.match(r"^\+\d{8,15}$", target):
        return "phone"

    if "@" in target:
        return "email"   # (future use)

    if "." in target:
        return "domain"

    return "username"   # ✅ ADD THIS


# =====================================================
# SUBDOMAIN CHANGE DETECTION
# =====================================================

def detect_subdomain_changes(target: str, current: List[Finding]):

    previous_rows = load_last_scan(target)

    if not previous_rows:
        return [], []

    previous = {row[0] for row in previous_rows}
    current_set = {f.value for f in current if f.type == "subdomain"}

    added = sorted(current_set - previous)
    removed = sorted(previous - current_set)

    return added, removed


# =====================================================
# MAIN ENGINE
# =====================================================

def run_scan(target: str, **kwargs) -> List[Finding]:

    start_time = time.time()

    # ---------- Extract optional args safely ----------
    run_wapiti = kwargs.get("run_wapiti", False)
    wapiti_mode = kwargs.get("wapiti_mode", "active")
    run_vt = kwargs.get("run_vt", False)

    only_live = kwargs.get("only_live", False)
    only_verified = kwargs.get("only_verified", False)
    min_confidence = kwargs.get("min_confidence", 0.0)

    print(f"\n[+] Starting OSINT scan for: {target}\n")

    # -------------------------------------------------
    # Load modules
    # -------------------------------------------------

    target_type = detect_target_type(target)
    modules = get_modules_for_target(target_type)

    print(f"[+] Loaded modules: {len(modules)}\n")

    raw_results: List[Finding] = []

    # -------------------------------------------------
    # MODULE EXECUTION
    # -------------------------------------------------

    for module in tqdm(modules, desc="Running modules", unit="module"):
        try:
            print(f"\n[*] Running module: {module.name}")
            raw_results.extend(module.run(target))
        except Exception as e:
            print(f"[!] {module.name} failed:", e)

    if not raw_results:
        print("[!] No findings")
        return []

    # -------------------------------------------------
    # CORRELATION
    # -------------------------------------------------

    correlated = correlate_findings(raw_results)

    # -------------------------------------------------
    # ENRICHMENT (ONLY FOR DOMAINS)
    # -------------------------------------------------

    domain_findings = [f for f in correlated if f.type == "subdomain"]
    other_findings = [f for f in correlated if f.type != "subdomain"]

    if domain_findings:
        domain_findings = enrich_findings_dns(domain_findings)
        domain_findings = enrich_findings_http(domain_findings)

    correlated = domain_findings + other_findings

    # -------------------------------------------------
    # VERIFICATION
    # -------------------------------------------------

    correlated = mark_verified(correlated)

    # -------------------------------------------------
    # CHANGE DETECTION
    # -------------------------------------------------

    if target_type == "domain":
        added, removed = detect_subdomain_changes(target, correlated)
    else:
        added, removed = [], []

    # -------------------------------------------------
    # SAVE SNAPSHOT
    # -------------------------------------------------

    save_findings(correlated)

    # -------------------------------------------------
    # PAGE CHANGE DETECTION
    # -------------------------------------------------

    if target_type == "domain":
        change_report = detect_changes(target)
    else:
        change_report = {
            "text_change_percent": 0,
            "new_links": [],
            "removed_links": []
        }

    # -------------------------------------------------
    # FILTERING
    # -------------------------------------------------

    filtered = apply_filters(
        correlated,
        only_live=only_live,
        only_verified=only_verified,
        min_confidence=min_confidence
    )

    # STRICT HTTP SUCCESS FILTER
    if only_live:
        strict_filtered = []
        for f in filtered:
            http = f.metadata.get("http", {})
            if http.get("alive") and http.get("status") == 200:
                strict_filtered.append(f)
        filtered = strict_filtered

    print(f"\n[+] Final findings after filtering: {len(filtered)}")

    # -------------------------------------------------
    # PRIORITIZATION
    # -------------------------------------------------

    filtered = prioritize_findings(filtered)

    # =====================================================
    # OPTIONAL: WAPITI SCAN
    # =====================================================

    wapiti_findings = []
    wapiti_pdf_path = None

    if run_wapiti and target_type == "domain":

        print("\n========= WAPITI SCAN =========\n")

        try:
            scanner = WapitiScanner()

            wapiti_findings = scanner.run_scan(
                target_url=f"https://{target}",
                mode=wapiti_mode
            )

            if hasattr(scanner, "last_pdf_path"):
                wapiti_pdf_path = scanner.last_pdf_path

        except Exception as e:
            print("[!] Wapiti failed:", e)

    # =====================================================
    # OPTIONAL: VIRUSTOTAL SCAN
    # =====================================================

    vt_results = None

    if run_vt and target_type == "domain":

        print("\n========= VIRUSTOTAL SCAN =========\n")

        try:
            vt = VirusTotalScanner()
            vt_results = vt.run_scan(target, correlated)
        except Exception as e:
            print("[!] VT failed:", e)

    # -------------------------------------------------
    # TREND ANALYSIS
    # -------------------------------------------------

    trend_metrics = calculate_trend_metrics(target)

    # -------------------------------------------------
    # SEVERITY ENGINE
    # -------------------------------------------------

    severity_events = build_severity_events(
        added_subdomains=added,
        removed_subdomains=removed,
        change_report=change_report,
        wapiti_findings=wapiti_findings,
        vt_results=vt_results
    )

    # -------------------------------------------------
    # ALERT ENGINE
    # -------------------------------------------------

    base_alerts = evaluate_alerts(
        added_subdomains=added,
        removed_subdomains=removed,
        page_change_report=change_report,
        trend_metrics=trend_metrics
    )

    wapiti_alerts = evaluate_wapiti_alerts(wapiti_findings)
    vt_alerts = evaluate_vt_alerts(vt_results)

    alerts = merge_all_alerts(base_alerts, vt_alerts, wapiti_alerts)

    # -------------------------------------------------
    # REPORT OUTPUT
    # -------------------------------------------------

    print("\n========= SUBDOMAIN CHANGES =========\n")

    if added:
        print("[+] New subdomains:")
        for s in added:
            print("   ", s)
    else:
        print("[+] No new subdomains")

    print()

    if removed:
        print("[-] Removed subdomains:")
        for s in removed:
            print("   ", s)
    else:
        print("[-] No removed subdomains")

    print("\n====================================\n")

    if target_type == "domain":
        print_change_report(change_report)

    print("\n========= SEVERITY REPORT =========\n")

    for event in severity_events:
        print(f"[{event['severity']}] {event['type']} → {event['value']}")

    print_alerts(alerts)
    print_trend_report(target)

    # -------------------------------------------------
    # CURRENT FINDINGS
    # -------------------------------------------------

    print("\n========= CURRENT FINDINGS =========\n")

    for f in filtered:

        if f.type == "phone":
            print_phone_result(f)

        elif f.type == "phone_lookup":
            print_truecaller_result(f)

        elif f.type.startswith("email"):
            print_email_result(f)

        elif f.type == "username":
            print_username_result(f)

        elif f.type == "username_search":
            print_username_search_result(f)

        else:
            print(f)

    print("\n===================================\n")
   
    # -------------------------------------------------
    # EMAIL REPORT
    # -------------------------------------------------

   # EMAIL REPORT (only for domain targets)

    if target_type == "domain":

        try:
            send_daily_summary(
                target=target,
                findings=filtered,
                change_report=change_report,
                trend_metrics=trend_metrics,
                vt_results=vt_results,
                wapiti_findings=wapiti_findings,
                alerts=alerts,
                wapiti_pdf=wapiti_pdf_path
            )
        except Exception as e:
            print("[!] Failed to send report email:", e)

    print(f"\n[✓] Scan finished in {round(time.time()-start_time,2)}s")

    surface = build_attack_surface(filtered)
    print_attack_surface(surface)

    return filtered