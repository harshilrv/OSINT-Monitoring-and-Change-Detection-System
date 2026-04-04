import difflib
import re

from core.snapshot_manager import (
    fetch_current_html,
    save_snapshot,
    load_latest_snapshot
)
from core.html_utils import prepare_content


# ----------------------------------
# Advanced diff %
# ----------------------------------

def diff_percent(old_html: str, new_html: str):

    if not old_html or not new_html:
        return 0.0

    # Text similarity
    old_text = re.sub(r"\s+", " ", old_html)
    new_text = re.sub(r"\s+", " ", new_html)

    text_ratio = difflib.SequenceMatcher(None, old_text, new_text).ratio()

    # Tag structure similarity
    old_tags = re.findall(r"<[^>]+>", old_html)
    new_tags = re.findall(r"<[^>]+>", new_html)
    tag_ratio = difflib.SequenceMatcher(None, old_tags, new_tags).ratio()

    # Attribute similarity
    old_attrs = re.findall(r'(id|class|data-[a-zA-Z0-9_-]+)="[^"]+"', old_html)
    new_attrs = re.findall(r'(id|class|data-[a-zA-Z0-9_-]+)="[^"]+"', new_html)
    attr_ratio = difflib.SequenceMatcher(None, old_attrs, new_attrs).ratio()

    combined_ratio = (
        (text_ratio * 0.6) +
        (tag_ratio * 0.25) +
        (attr_ratio * 0.15)
    )

    change = (1 - combined_ratio) * 100

    if 0 < change < 0.35:
        change += 0.2

    return round(change, 2)


# ----------------------------------
# Change detection
# ----------------------------------

def detect_changes(target: str):

    url = f"https://{target}"

    current_html = fetch_current_html(url)

    if not current_html:
        return {"baseline": False, "error": "Could not fetch page"}

    previous_html = load_latest_snapshot(target)

    # Baseline
    if previous_html is None:

        save_snapshot(target, current_html)

        return {
            "baseline": True,
            "changes": None
        }

    old_content = prepare_content(previous_html)
    new_content = prepare_content(current_html)

    text_change = diff_percent(previous_html, current_html)

    new_links = new_content["links"] - old_content["links"]
    removed_links = old_content["links"] - new_content["links"]

    save_snapshot(target, current_html)

    return {
        "baseline": False,
        "text_change_percent": text_change,
        "new_links": list(new_links),
        "removed_links": list(removed_links)
    }


# ----------------------------------
# Clean report
# ----------------------------------

def print_change_report(report):

    if report.get("baseline"):
        print("\n[INFO] Baseline snapshot created\n")
        return

    if "error" in report:
        print("[!] Error:", report["error"])
        return

    print("\n========= CHANGE REPORT =========\n")

    print(f"Text changed: {report['text_change_percent']} %\n")

    if report["new_links"]:
        print("New links:")
        for l in report["new_links"]:
            print("  +", l)
    else:
        print("No new links")

    print()

    if report["removed_links"]:
        print("Removed links:")
        for l in report["removed_links"]:
            print("  -", l)
    else:
        print("No removed links")

    print("\n===============================\n")
