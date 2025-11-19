"""
XSS detection: inject payloads into GET params and forms and look for reflection.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult
import requests
from bs4 import BeautifulSoup
from typing import List, Dict
import time

REQUEST_HEADERS = {"User-Agent": "vulnscanner-xss/1.0"}

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '";alert(1);//',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]


def inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [qs.get(param, [""])[0] + payload]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    newp = ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
    return urlunparse(newp)


def detect_reflection(response_text: str, payload: str) -> bool:
    return payload in response_text


def scan_url_for_xss(url: str, session: requests.Session = None) -> List[Dict]:
    if session is None:
        session = requests.Session()
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    params = list(parse_qs(p.query).keys())
    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(url, param, payload)
            try:
                r = session.get(test_url, headers=REQUEST_HEADERS, timeout=5)
            except Exception:
                continue
            if detect_reflection(r.text, payload):
                findings.append({
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "evidence_snippet": get_snippet(r.text, payload),
                    "status": r.status_code,
                })
    return findings


def get_snippet(text: str, payload: str, context: int = 60) -> str:
    idx = text.find(payload)
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(text), idx + len(payload) + context)
    return text[start:end]


def scan_forms_for_xss(forms: List[Dict], session: requests.Session = None) -> List[Dict]:
    if session is None:
        session = requests.Session()
    findings = []
    for form in forms:
        method = form.get("method", "get").lower()
        action = form.get("action")
        inputs = form.get("inputs", [])
        for payload in XSS_PAYLOADS:
            data = {inp["name"]: payload for inp in inputs}
            try:
                if method == "post":
                    r = session.post(action, data=data, headers=REQUEST_HEADERS, timeout=5)
                else:
                    r = session.get(action, params=data, headers=REQUEST_HEADERS, timeout=5)
            except Exception:
                continue
            if detect_reflection(r.text, payload):
                findings.append({
                    "form": form,
                    "payload": payload,
                    "evidence_snippet": get_snippet(r.text, payload),
                    "status": r.status_code,
                })
            time.sleep(0.1)
    return findings


def scan(urls: List[str], forms: List[Dict], session: requests.Session = None) -> List[Dict]:
    if session is None:
        session = requests.Session()
    all_findings = []
    for url in urls:
        all_findings.extend(scan_url_for_xss(url, session))
        time.sleep(0.1)
    all_findings.extend(scan_forms_for_xss(forms, session))
    return all_findings


if __name__ == "__main__":
    import sys
    sess = requests.Session()
    if len(sys.argv) > 1:
        print(scan([sys.argv[1]], [] , sess))
