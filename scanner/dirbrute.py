"""
Directory brute-force using a wordlist. Synchronous, records interesting status codes.
"""
import requests
from typing import List, Dict
from pathlib import Path
from tqdm import tqdm

REQUEST_HEADERS = {"User-Agent": "vulnscanner-dirbrute/1.0"}


def load_wordlist(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        return []
    items = [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    return items


def probe_paths(base_url: str, wordlist: List[str], session: requests.Session = None, extensions: List[str] = None) -> List[Dict]:
    if session is None:
        session = requests.Session()
    if extensions is None:
        # Reduced extensions for faster scanning
        extensions = ["", "/"]
    findings = []
    for word in tqdm(wordlist, desc="dirbrute"):
        for ext in extensions:
            path = f"/{word}{ext}" if not word.startswith("/") else f"{word}{ext}"
            url = base_url.rstrip("/") + path
            try:
                r = session.get(url, headers=REQUEST_HEADERS, timeout=4, allow_redirects=True)
            except Exception:
                continue
            if r.status_code in (200, 301, 302, 403):
                findings.append({"url": url, "status": r.status_code, "length": len(r.text)})
    return findings


if __name__ == "__main__":
    import sys
    sess = requests.Session()
    wl = load_wordlist(sys.argv[1]) if len(sys.argv) > 1 else []
    res = probe_paths(sys.argv[2] if len(sys.argv) > 2 else "http://localhost", wl, sess)
    print(res)
