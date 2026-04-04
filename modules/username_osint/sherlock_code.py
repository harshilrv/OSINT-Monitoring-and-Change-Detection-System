import subprocess
import re


def username_osint(username):

    try:
        result = subprocess.run(
            ["sherlock", username],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        output = result.stdout

        findings = []

        # Match lines like:
        # [+] GitHub: https://github.com/username
        pattern = re.findall(r"\[\+\]\s+(.+?):\s+(https?://[^\s]+)", output)

        for platform, url in pattern:
            findings.append({
                "platform": platform.strip().lower(),
                "url": url
            })

        # 🔥 REMOVE DUPLICATES
        unique = []
        seen = set()

        for f in findings:
            key = (f["platform"], f["url"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    except Exception:
        return []


def run(username):
    return username_osint(username)