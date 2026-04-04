import re
from bs4 import BeautifulSoup


def normalize_html(html: str):

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator=" ")

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_links(html: str):

    soup = BeautifulSoup(html, "html.parser")

    links = set()

    for a in soup.find_all("a", href=True):
        links.add(a["href"].strip())

    return links


def prepare_content(html: str):

    return {
        "text": normalize_html(html),
        "links": extract_links(html)
    }
