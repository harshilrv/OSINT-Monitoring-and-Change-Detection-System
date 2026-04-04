import requests
from typing import List
from core.models import Finding


def probe_url(url: str):

    try:
        r = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "OSINT-Engine"}
        )

        title = ""
        if "<title" in r.text.lower():
            try:
                title = r.text.lower().split("<title")[1].split(">")[1].split("</title>")[0][:80]
            except Exception:
                title = ""

        return {
            "status": r.status_code,
            "title": title,
            "server": r.headers.get("Server"),
            "content_type": r.headers.get("Content-Type")
        }

    except Exception:
        return None


def enrich_findings_http(findings: List[Finding]) -> List[Finding]:

    for f in findings:

        if f.type != "subdomain":
            continue

        url = f"https://{f.value}"

        result = probe_url(url)

        if not result:
            f.metadata["http"] = {"alive": False}
            continue

        f.metadata["http"] = {
            "alive": True,
            "status": result["status"],
            "title": result["title"],
            "server": result["server"],
            "content_type": result["content_type"]
        }

    return findings