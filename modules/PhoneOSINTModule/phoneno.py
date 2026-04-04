import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import json


def load_countries_data(json_path):

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_country_by_calling_code(countries_data, calling_code):

    if not countries_data:
        return None

    if not calling_code.startswith("+"):
        calling_code = "+" + calling_code

    for country in countries_data:
        if "callingCodes" in country:
            if calling_code in country["callingCodes"]:
                return country

    return None


def analyze_phone_to_dict(number_string, countries_data):

    parsed = phonenumbers.parse(number_string, None)

    country_code = parsed.country_code
    national_number = parsed.national_number
    region = phonenumbers.region_code_for_number(parsed)

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)

    location = geocoder.description_for_number(parsed, "en")
    carrier_name = carrier.name_for_number(parsed, "en")

    tz = timezone.time_zones_for_number(parsed)

    country_info = find_country_by_calling_code(countries_data, f"+{country_code}")

    return {
        "country_code": country_code,
        "national_number": national_number,
        "region": region,
        "valid": valid,
        "possible": possible,
        "location": location,
        "carrier": carrier_name,
        "timezone": list(tz),
        "country_info": country_info
    }