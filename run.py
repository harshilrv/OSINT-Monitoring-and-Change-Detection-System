from core.orchestrator import run_scan

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="osint-engine",
        description="OSINT Attack Surface Intelligence Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        help="Target domain to scan"
    )

    parser.add_argument(
        "--wapiti",
        action="store_true",
        help="Run Wapiti vulnerability scanner"
    )

    parser.add_argument(
        "--passive",
        action="store_true",
        help="Run Wapiti in passive mode"
    )

    parser.add_argument(
        "--vt",
        action="store_true",
        help="Check domains using VirusTotal reputation API"
    )

    parser.add_argument(
        "--only-live",
        action="store_true",
        help="Show only live HTTP hosts"
    )

    parser.add_argument(
        "--only-verified",
        action="store_true",
        help="Show only DNS-verified hosts"
    )

    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum confidence score filter (0.0 – 1.0)"
    )

    args = parser.parse_args()

    mode = "passive" if args.passive else "active"

    results = run_scan(
        target=args.target,
        run_wapiti=args.wapiti,
        wapiti_mode=mode,
        run_vt=args.vt,
        only_live=args.only_live,
        only_verified=args.only_verified,
        min_confidence=args.min_confidence
    )

    print(f"\n[+] Scan complete. Found {len(results)} findings.\n")
