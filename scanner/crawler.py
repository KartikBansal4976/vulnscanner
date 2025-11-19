"""
Crawler: BFS crawling within same domain, extract links and forms.
"""
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple, Set

REQUEST_HEADERS = {
    "User-Agent": "vulnscanner/1.0 (+https://example.com)"
}


def is_same_domain(root: str, url: str) -> bool:
    return urlparse(root).netloc == urlparse(url).netloc


def normalize_url(base: str, link: str) -> str:
    return urljoin(base, link)


def extract_forms(soup: BeautifulSoup, base_url: str) -> List[Dict]:
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or base_url
        action = normalize_url(base_url, action)
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = inp.get("type", "text")
            inputs.append({"name": name, "type": itype})
        forms.append({"method": method, "action": action, "inputs": inputs})
    return forms


def extract_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        full = normalize_url(base_url, href)
        links.add(full)
    return list(links)


def crawl(start_url: str, max_depth: int = 2, session: requests.Session = None, delay: float = 0.1, max_pages: int = 50) -> Tuple[List[str], List[Dict]]:
    """
    Crawl pages starting from start_url up to max_depth (BFS).

    Returns: (pages, forms)
    pages: list of found page URLs
    forms: list of forms found with details
    """
    if session is None:
        session = requests.Session()
    pages: List[str] = []
    forms: List[Dict] = []
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]

    print(f"[Crawler] Starting with URL: {start_url}, max_depth: {max_depth}, max_pages: {max_pages}")
    
    while queue:
        # Stop if we've reached max pages limit
        if len(pages) >= max_pages:
            print(f"[Crawler] Reached max_pages limit ({max_pages}), stopping early")
            break
            
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if depth > max_depth:
            continue
        
        print(f"[Crawler] Fetching {url} (depth {depth})...")
        try:
            resp = session.get(url, headers=REQUEST_HEADERS, timeout=6)
            print(f"[Crawler] Got response: {resp.status_code}")
        except Exception as e:
            print(f"[Crawler] Error fetching {url}: {e}")
            continue
        
        pages.append(url)
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            print(f"[Crawler] Skipping non-HTML content: {content_type}")
            continue
        
        soup = BeautifulSoup(resp.text, "lxml")
        page_forms = extract_forms(soup, url)
        forms.extend(page_forms)
        print(f"[Crawler] Found {len(page_forms)} forms on this page")
        
        links = extract_links(soup, url)
        new_links = 0
        for link in links:
            if is_same_domain(start_url, link):
                if link not in visited:
                    queue.append((link, depth + 1))
                    new_links += 1
        print(f"[Crawler] Found {new_links} new links (total in queue: {len(queue)})")
    
    print(f"[Crawler] Finished! Total pages: {len(pages)}, Total forms: {len(forms)}")
    return pages, forms


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        p, f = crawl(url, max_depth=1)
        print("Pages:", p)
        print("Forms:", f)
