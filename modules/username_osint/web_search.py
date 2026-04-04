from typing import List
from core.models import Finding

from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from bs4 import BeautifulSoup
from urllib.parse import unquote, quote


def decode_yahoo_url(href):
    if "/RU=" in href:
        try:
            ru = href.split("/RU=")[1].split("/")[0]
            return unquote(ru)
        except Exception:
            pass
    return href


def run(username: str) -> List[Finding]:

    spaced = username.strip()
    underscored = spaced.replace(" ", "_")
    nospaced = spaced.replace(" ", "")
    dotted = spaced.replace(" ", ".")

    query = f'"{nospaced}" OR "{spaced}" OR "{underscored}" OR "{dotted}"'

    results = []
    seen = set()

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--window-size=1920,1080")

    driver = webdriver.Edge(options=options)

    try:
        url = f"https://search.yahoo.com/search?p={quote(query)}&b=1&pz=10"
        driver.get(url)

        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div#web li"))
        )

        soup = BeautifulSoup(driver.page_source, "html.parser")

        blocks = soup.select("div#web li")

        for g in blocks:

            title_el = g.select_one("h3 a")
            snippet_el = g.select_one("p")

            if not title_el:
                continue

            href = title_el.get("href", "")
            if not href.startswith("http"):
                continue

            href = decode_yahoo_url(href)

            if href in seen:
                continue

            seen.add(href)

            results.append(
                Finding(
                    type="username_search",
                    value=username,
                    source="yahoo",
                    target=username,
                    confidence=0.6,
                    metadata={
                        "title": title_el.text.strip(),
                        "url": href,
                        "snippet": snippet_el.text.strip()[:120] if snippet_el else ""
                    }
                )
            )

    except Exception as e:
        print("[!] Yahoo search failed:", e)

    finally:
        driver.quit()

    return results[:20]