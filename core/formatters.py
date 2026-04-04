def print_phone_result(finding):

    data = finding.metadata

    print("\n📱 PHONE INTELLIGENCE REPORT")
    print("────────────────────────────────────────")

    print(f"Number        : {finding.value}")
    print(f"Carrier       : {data.get('carrier', 'Unknown')}")
    print(f"Location      : {data.get('location', 'Unknown')}")
    print(f"Region        : {data.get('region', 'Unknown')}")

    print(f"Valid Number  : {'Yes' if data.get('valid') else 'No'}")
    print(f"Possible      : {'Yes' if data.get('possible') else 'No'}")

    tz = data.get("timezone", [])
    if tz:
        print(f"Timezone      : {', '.join(tz)}")

    country = data.get("country_info", {})

    if country:
        print("\n🌍 COUNTRY INFORMATION")
        print("────────────────────────────────────────")

        name = country.get("name", {}).get("common", "Unknown")
        capital = country.get("capital", ["Unknown"])[0]
        region = country.get("region", "Unknown")
        population_area = country.get("area", "Unknown")

        print(f"Country       : {name}")
        print(f"Capital       : {capital}")
        print(f"Region        : {region}")
        print(f"Area          : {population_area} km²")

    print("\nConfidence    :", finding.confidence)

    print("────────────────────────────────────────\n")


def print_truecaller_result(finding):

    data = finding.metadata

    print("\n☎ TRUECALLER INTELLIGENCE")
    print("────────────────────────────────")

    print(f"Number        : {finding.value}")
    print(f"Name          : {data.get('name','Unknown')}")
    print(f"Carrier       : {data.get('carrier','Unknown')}")
    print(f"City          : {data.get('city','Unknown')}")

    print(f"\nSpam Risk     : {data.get('risk_level','Unknown')}")
    print(f"Reports       : {data.get('report_count',0)}")

    tags = data.get("tags", [])
    if tags:
        print(f"Tags          : {', '.join(tags)}")

    emails = data.get("emails", [])
    if emails:
        print(f"Emails        : {', '.join(emails)}")

    print("────────────────────────────────\n")


def print_username_result(f):

    data = f.metadata

    print("\n👤 USERNAME INTELLIGENCE")
    print("────────────────────────")

    print(f"Username  : {f.value}")

    # Support multiple results
    profiles = data.get("profiles", [])

    if profiles:
        print(f"Found on  : {len(profiles)} platforms\n")

        for p in profiles[:10]:  # limit output
            platform = p.get("platform", "unknown")
            url = p.get("url", "")
            source = p.get("source", "unknown")

            print(f"  • {platform} → {url}  [{source}]")

    else:
        print(f"Platform  : {data.get('platform', 'unknown')}")
        print(f"URL       : {data.get('url', 'N/A')}")

    print("────────────────────────\n")


# ===============================
# NEW: EMAIL FORMATTER
# ===============================

def print_email_result(f):

    data = f.metadata

    # -------------------------
    # EMAIL BASIC
    # -------------------------
    if f.type == "email":

        print("\n📧 EMAIL INTELLIGENCE")
        print("────────────────────────")

        print(f"Email        : {f.value}")
        print(f"Domain       : {data.get('domain', 'Unknown')}")

        print(f"SPF          : {'Yes' if data.get('spf') else 'No'}")
        print(f"DMARC        : {'Yes' if data.get('dmarc') else 'No'}")

        mx = data.get("mx_records", [])
        if mx:
            print(f"Mail Servers : {len(mx)} found")

        print("────────────────────────\n")

    # -------------------------
    # ACCOUNTS
    # -------------------------
    elif f.type == "email_accounts":

        accounts = data.get("accounts", [])

        print("\n🌐 LINKED ACCOUNTS")
        print("────────────────────────")

        print(f"Found        : {len(accounts)}")

        for acc in accounts:
            print(f"  • {acc}")

        print("────────────────────────\n")

    # -------------------------
    # BREACH
    # -------------------------
    elif f.type == "email_breach":

        status = data.get("breached")

        if status is True:
            status_str = "⚠️ BREACHED"
        elif status is False:
            status_str = "✅ CLEAN"
        else:
            status_str = "UNKNOWN"

        print("\n🔐 BREACH STATUS")
        print("────────────────────────")
        print(f"Status       : {status_str}")
        print("────────────────────────\n")
        


def print_username_search_result(f):

    data = f.metadata

    print("\n🔎 SEARCH RESULTS")
    print("────────────────────────")
    print(f"Title  : {data.get('title')}")
    print(f"URL    : {data.get('url')}")
    print(f"Snippet: {data.get('snippet')}")