"""
Simple SQLi detection module.

Implements error-based and boolean-differential checks for GET parameters.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult
import requests
from typing import List, Dict
import time

REQUEST_HEADERS = {
    "User-Agent": "vulnscanner-sqli/1.0"
}

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query():",
    "mysql_fetch",
    "syntax error at or near",
]

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    '" OR ""="',
    "'" ,
    "' AND 1=1 -- ",
    "' AND 1=2 -- ",
]


def inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [qs.get(param, [""])[0] + payload]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    newp = ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
    return urlunparse(newp)


def baseline_response(url: str, session: requests.Session) -> str:
    try:
        r = session.get(url, headers=REQUEST_HEADERS, timeout=5)
        return r.text
    except Exception:
        return ""


def detect_error_signatures(text: str) -> List[str]:
    found = []
    lower = text.lower()
    for s in SQL_ERRORS:
        if s in lower:
            found.append(s)
    return found


def scan_url_for_sqli(url: str, session: requests.Session = None) -> List[Dict]:
    """
    Scan a single URL with GET parameters for SQLi.

    Returns list of findings containing parameter, payload, evidence, type
    """
    if session is None:
        session = requests.Session()
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    params = list(parse_qs(p.query).keys())
    base = baseline_response(url, session)
    base_len = len(base)
    for param in params:
        for payload in SQL_PAYLOADS:
            test_url = inject_param(url, param, payload)
            try:
                r = session.get(test_url, headers=REQUEST_HEADERS, timeout=5)
            except Exception:
                continue
            text = r.text
            # error-based
            errors = detect_error_signatures(text)
            if errors:
                findings.append({
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "type": "error-based",
                    "evidence": errors,
                    "status": r.status_code,
                })
                continue
            # boolean differential: compare responses for true/false payloads
            if "1=1" in payload or "AND 1=1" in payload:
                # try payload that makes condition false
                false_payload = payload.replace("1=1", "1=2")
                true_url = inject_param(url, param, payload)
                false_url = inject_param(url, param, false_payload)
                try:
                    rt = session.get(true_url, headers=REQUEST_HEADERS, timeout=5)
                    rf = session.get(false_url, headers=REQUEST_HEADERS, timeout=5)
                except Exception:
                    continue
                if abs(len(rt.text) - len(rf.text)) > max(20, base_len * 0.05):
                    findings.append({
                        "url": url,
                        "param": param,
                        "payload": payload + " / " + false_payload,
                        "type": "boolean-diff",
                        "evidence": {"len_true": len(rt.text), "len_false": len(rf.text)},
                        "status": (rt.status_code, rf.status_code),
                    })
                    continue
            # length-based heuristic relative to baseline
            if base_len and abs(len(text) - base_len) > max(50, base_len * 0.1):
                findings.append({
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "type": "length-diff",
                    "evidence": {"base_len": base_len, "len": len(text)},
                    "status": r.status_code,
                })
    return findings


def scan(urls: List[str], session: requests.Session = None) -> List[Dict]:
    if session is None:
        session = requests.Session()
    all_findings = []
    for url in urls:
        res = scan_url_for_sqli(url, session)
        if res:
            all_findings.extend(res)
        time.sleep(0.2)
    return all_findings


if __name__ == "__main__":
    import sys
    sess = requests.Session()
    if len(sys.argv) > 1:
        print(scan([sys.argv[1]], sess))
