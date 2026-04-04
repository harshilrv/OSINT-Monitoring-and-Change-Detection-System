from core.models import Finding
from core.base_module import BaseModule
import os

from .phoneno import analyze_phone_to_dict, load_countries_data
from .auth import is_session_saved, login
from .search import search_number


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COUNTRIES_PATH = os.path.join(BASE_DIR, "countries.json")


class PhoneOSINTModule(BaseModule):

    name = "phone_osint"

    # 🔴 THIS WAS MISSING
    supported_targets = ["phone"]

    def run(self, target):

        findings = []

        if not target.startswith("+"):
            return []

        try:

            countries = load_countries_data(COUNTRIES_PATH)

            info = analyze_phone_to_dict(target, countries)

            findings.append(
                Finding(
                    type="phone",
                    value=target,
                    source="phonenumbers",
                    target=target,
                    confidence=0.8,
                    metadata=info
                )
            )

            if not is_session_saved():
                login()

            result = search_number(target.lstrip("+"), "in")

            findings.append(
                Finding(
                    type="phone_lookup",
                    value=target,
                    source="truecaller",
                    target=target,
                    confidence=0.9,
                    metadata=result
                )
            )

        except Exception as e:
            print("[!] Phone OSINT module error:", e)

        return findings