from core.base_module import BaseModule
from core.models import Finding

from . import sherlock_code
from . import whatsmyname_code
from . import social_checker

# ✅ Yahoo search integration
from modules.username_osint.web_search import run as yahoo_search


class UsernameOSINTModule(BaseModule):

    name = "username_osint"
    supported_targets = ["username"]

    def run(self, target):

        username = target.strip()

        profiles = []
        search_results = []

        # ---------------------------
        # Sherlock
        # ---------------------------
        try:
            results = sherlock_code.run(username)
            for r in results or []:
                if isinstance(r, dict):
                    r["source"] = "sherlock"   # ✅ FIX
                    profiles.append(r)
        except Exception as e:
            print("[!] Sherlock failed:", e)

        # ---------------------------
        # WhatsMyName
        # ---------------------------
        try:
            results = whatsmyname_code.run(username)
            for r in results or []:
                if isinstance(r, dict):
                    r["source"] = "whatsmyname"
                    profiles.append(r)
        except Exception as e:
            print("[!] WhatsMyName failed:", e)

        # ---------------------------
        # Social Checker
        # ---------------------------
        try:
            results = social_checker.run(username)
            for r in results or []:
                if isinstance(r, dict):
                    r["source"] = "social_checker"   # ✅ FIX
                    profiles.append(r)
        except Exception as e:
            print("[!] Social Checker failed:", e)

        # ---------------------------
        # CLEAN + FILTER + DEDUP
        # ---------------------------
        clean_profiles = []
        seen = set()

        for p in profiles:

            if not isinstance(p, dict):
                continue

            platform = p.get("platform", "").lower()
            url = p.get("url", "")
            source = p.get("source", "unknown")

            # 🚫 remove junk
            if not platform or not url or "api." in url:
                continue

            key = (platform, url)

            if key not in seen:
                seen.add(key)
                clean_profiles.append({
                    "platform": platform,
                    "url": url,
                    "source": source
                })

        # ---------------------------
        # Yahoo Search
        # ---------------------------
        try:
            results = yahoo_search(username)
            search_results = results or []
        except Exception as e:
            print("[!] Yahoo search failed:", e)

        findings = []

        # ---------------------------
        # FINAL USERNAME FINDING
        # ---------------------------
        if clean_profiles:
            findings.append(
                Finding(
                    type="username",
                    value=username,
                    source="username_osint",
                    target=target,
                    confidence=0.9,
                    metadata={"profiles": clean_profiles}
                )
            )

        # ---------------------------
        # ADD SEARCH RESULTS
        # ---------------------------
        findings.extend(search_results)

        return findings