"""
Analyzer module: adds passive and optional active checks.

Passive checks (safe):
 - Security header analysis
 - CORS header checks
 - CSRF token presence in discovered forms
 - Sensitive info detection in page bodies
 - Parameter pollution detection (simple)

Active checks (only run when unsafe=True):
 - SSRF payload injection into GET params
 - LFI/RFI payload injection into GET params
 - Command injection payloads into GET params
 - Open redirect checks
 - IDOR numeric increment tests

Warning: Active checks may be intrusive; only enable with --unsafe and against targets you own or have permission to test.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult
from urllib.parse import urljoin
import requests
from typing import List, Dict, Any
import re
import ssl
import socket
import datetime
import time

REQUEST_HEADERS = {"User-Agent": "vulnscanner-analyzer/1.0"}

# Payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",
]

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../../etc/hosts",
    "php://filter/convert.base64-encode/resource=index.php",
]

CMD_PAYLOADS = ["; id", "; whoami", "&& ls", "| cat /etc/passwd"]

REDIRECT_TEST = "https://example.com/"


def inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [qs.get(param, [""])[0] + payload]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    newp = ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
    return urlunparse(newp)


def check_security_headers(resp: requests.Response) -> Dict[str, Any]:
    headers = resp.headers
    issues = []
    needed = ["x-frame-options", "content-security-policy", "x-content-type-options", "strict-transport-security", "x-xss-protection"]
    for h in needed:
        if h not in {k.lower() for k in headers.keys()}:
            issues.append(f"Missing header: {h}")
    # check CORS
    cors = headers.get("Access-Control-Allow-Origin")
    if cors == "*":
        issues.append("CORS: Access-Control-Allow-Origin: *")
    return {"headers": dict(headers), "issues": issues}


def check_csrf(forms: List[Dict]) -> List[Dict]:
    findings = []
    token_names = ["csrf", "_csrf", "csrf_token", "authenticity_token", "_token"]
    for form in forms:
        inputs = form.get("inputs", [])
        names = [i.get("name", "").lower() for i in inputs]
        if not any(any(t in n for t in token_names) for n in names):
            findings.append({"form": form, "issue": "missing_csrf_token"})
    return findings


def detect_sensitive_info(text: str) -> List[Dict]:
    findings = []
    # .git exposures
    if ".git" in text:
        findings.append({"type": "possible_git", "evidence": ".git found in body"})
    # env file patterns
    if re.search(r"\bDB_PASSWORD\b|\bAPI_KEY\b|aws_access_key_id", text, re.I):
        findings.append({"type": "possible_secret", "evidence": "high-entropy or secret-like strings"})
    # stack trace
    if "Traceback (most recent call last)" in text or "Exception in thread" in text:
        findings.append({"type": "stack_trace", "evidence": "stack trace visible"})
    return findings


def param_pollution_test(url: str, session: requests.Session) -> Dict:
    p = urlparse(url)
    if not p.query:
        return {}
    # create duplicate param
    qs = parse_qs(p.query, keep_blank_values=True)
    for k in list(qs.keys()):
        # build url with duplicate k
        dup = f"{k}={qs[k][0]}&{k}={qs[k][0]}"
        new_q = dup
        newp = ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
        nu = urlunparse(newp)
        try:
            r = session.get(nu, headers=REQUEST_HEADERS, timeout=8)
        except Exception:
            continue
        if r.status_code == 200 and r.text != session.get(url, headers=REQUEST_HEADERS, timeout=8).text:
            return {"url": url, "param": k, "issue": "parameter_pollution", "status": r.status_code}
    return {}


def check_open_redirect(url: str, session: requests.Session, unsafe: bool = False) -> List[Dict]:
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    params = list(parse_qs(p.query).keys())
    for param in params:
        test_url = inject_param(url, param, REDIRECT_TEST)
        try:
            r = session.get(test_url, headers=REQUEST_HEADERS, timeout=3, allow_redirects=False)
        except Exception:
            continue
        if r.is_redirect or r.status_code in (301, 302, 303):
            loc = r.headers.get("Location", "")
            if REDIRECT_TEST in loc:
                findings.append({"url": url, "param": param, "issue": "open_redirect", "location": loc})
    return findings


def check_idor(url: str, session: requests.Session, unsafe: bool = False) -> List[Dict]:
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    qs = parse_qs(p.query)
    for k, v in qs.items():
        if v and v[0].isdigit():
            orig = session.get(url, headers=REQUEST_HEADERS, timeout=3)
            new_val = str(int(v[0]) + 1)
            qs[k] = [new_val]
            new_q = urlencode({kk: vv[0] for kk, vv in qs.items()})
            newp = ParseResult(p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
            nu = urlunparse(newp)
            try:
                rnew = session.get(nu, headers=REQUEST_HEADERS, timeout=3)
            except Exception:
                continue
            # crude: if both responses contain similar identifying markers and status 200 and differ -> possible IDOR
            if orig.status_code == 200 and rnew.status_code == 200 and orig.text != rnew.text:
                findings.append({"url": url, "param": k, "orig_len": len(orig.text), "new_len": len(rnew.text)})
    return findings


def ssrf_lfi_cmd_tests(urls: List[str], session: requests.Session, unsafe: bool) -> List[Dict]:
    findings = []
    if not unsafe:
        return findings
    for url in urls:
        p = urlparse(url)
        if not p.query:
            continue
        params = list(parse_qs(p.query).keys())
        for param in params:
            # SSRF
            for payload in SSRF_PAYLOADS:
                test_url = inject_param(url, param, payload)
                try:
                    r = session.get(test_url, headers=REQUEST_HEADERS, timeout=6)
                except Exception:
                    continue
                # If metadata content appears or connection reflects, flag
                if "169.254.169.254" in r.text or "meta-data" in r.text:
                    findings.append({"url": url, "param": param, "payload": payload, "type": "ssrf", "status": r.status_code})
            # LFI
            for payload in LFI_PAYLOADS:
                test_url = inject_param(url, param, payload)
                try:
                    r = session.get(test_url, headers=REQUEST_HEADERS, timeout=6)
                except Exception:
                    continue
                if "root:x:" in r.text or "/etc/passwd" in r.text:
                    findings.append({"url": url, "param": param, "payload": payload, "type": "lfi", "status": r.status_code})
            # Command injection
            for payload in CMD_PAYLOADS:
                test_url = inject_param(url, param, payload)
                try:
                    r = session.get(test_url, headers=REQUEST_HEADERS, timeout=6)
                except Exception:
                    continue
                if "uid=" in r.text or "uid=" in r.text.lower() or "root:x:" in r.text:
                    findings.append({"url": url, "param": param, "payload": payload, "type": "cmd_injection", "status": r.status_code})
    return findings


def ssl_check(hostname: str) -> Dict:
    info = {"host": hostname}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        # parse notBefore/notAfter
        notAfter = cert.get('notAfter')
        if notAfter:
            expiry = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z') if isinstance(notAfter, str) else None
            info['notAfter'] = notAfter
        info['cert_subject'] = cert.get('subject')
    except Exception as e:
        info['error'] = str(e)
    return info


def check_cookie_security(resp: requests.Response) -> List[Dict]:
    findings = []
    # Look for Set-Cookie header and check for flags
    sc = resp.headers.get('Set-Cookie')
    if not sc:
        return findings
    # naive split for multiple cookies
    parts = sc.split(',') if ',' in sc else [sc]
    for part in parts:
        p = part.strip()
        cookie_name = p.split('=')[0]
        attrs = p.lower()
        missing = []
        if 'httponly' not in attrs:
            missing.append('HttpOnly')
        if 'secure' not in attrs:
            missing.append('Secure')
        if 'samesite' not in attrs:
            missing.append('SameSite')
        if missing:
            findings.append({'cookie': cookie_name, 'missing_flags': missing, 'raw': p})
    return findings


def check_cors_reflection(url: str, session: requests.Session) -> Dict:
    """Send a request with a custom Origin and see if it's reflected in Access-Control-Allow-Origin."""
    sentinel = 'https://vulnscanner-test.example'
    try:
        r = session.get(url, headers={**REQUEST_HEADERS, 'Origin': sentinel}, timeout=3)
    except Exception:
        return {}
    acao = r.headers.get('Access-Control-Allow-Origin')
    if not acao:
        return {'url': url, 'issue': 'no_cors_header'}
    if acao == '*' or acao == sentinel:
        return {'url': url, 'issue': 'cors_reflect', 'value': acao}
    return {'url': url, 'acao': acao}


def rate_limit_test(url: str, session: requests.Session, attempts: int = 6) -> Dict:
    """Perform a gentle rate-limit detection by sending several quick requests.
    Returns a dict describing whether 429 or throttling behavior was observed.
    """
    results = {'url': url, 'attempts': attempts, '429_seen': False, 'timings': []}
    for i in range(attempts):
        try:
            t0 = datetime.datetime.now()
            r = session.get(url, headers=REQUEST_HEADERS, timeout=8)
            t1 = datetime.datetime.now()
            delta = (t1 - t0).total_seconds()
            results['timings'].append(delta)
            if r.status_code == 429:
                results['429_seen'] = True
                break
        except Exception:
            results['timings'].append(None)
    # simple heuristic: if timing of last requests significantly higher than first => possible throttling
    times = [t for t in results['timings'] if t]
    if len(times) >= 3 and max(times) > (sum(times) / len(times)) * 3:
        results['throttling_suspected'] = True
    return results


def detect_file_uploads(forms: List[Dict]) -> List[Dict]:
    findings = []
    for form in forms:
        enctype = form.get('enctype', '') or ''
        inputs = form.get('inputs', [])
        has_file = any(i.get('type', '').lower() == 'file' for i in inputs)
        if has_file or 'multipart/form-data' in enctype.lower():
            findings.append({'form': form, 'issue': 'file_upload_form'})
    return findings


def attempt_file_upload(form: Dict, session: requests.Session) -> Dict:
    """Try a minimal, safe file upload if the form action is available. This is intrusive and only run when unsafe=True."""
    action = form.get('action') or '/'
    method = (form.get('method') or 'post').lower()
    inputs = form.get('inputs', [])
    # pick a file input name if present
    file_input = None
    for i in inputs:
        if i.get('type', '').lower() == 'file':
            file_input = i.get('name') or 'file'
            break
    if not file_input:
        return {'error': 'no_file_input'}
    files = {file_input: ('vulnscanner.txt', b'vulnscanner-file-test', 'text/plain')}
    try:
        if method == 'post':
            r = session.post(action, files=files, headers=REQUEST_HEADERS, timeout=10)
        else:
            r = session.put(action, files=files, headers=REQUEST_HEADERS, timeout=10)
    except Exception as e:
        return {'error': str(e)}
    return {'status_code': r.status_code, 'len': len(r.content), 'location': r.headers.get('Location')}


def brute_force_login_tests(forms: List[Dict], session: requests.Session, unsafe: bool = False, credentials: List = None, max_attempts: int = 4, delay: float = 1.5) -> List[Dict]:
    """Controlled credential stuffing / brute-force tests.
    - Only runs when unsafe=True.
    - Uses a small built-in credential list by default.
    - Respects a delay between attempts and limits attempts per form.
    - Returns a list of attempt results with minimal info (status_code, len).
    """
    findings = []
    if not unsafe:
        return findings
    if credentials is None:
        credentials = [("admin", "admin"), ("admin", "password"), ("test", "test"), ("admin", "123456")]

    for form in forms:
        inputs = form.get('inputs', [])
        has_password = any(i.get('type', '').lower() == 'password' for i in inputs)
        if not has_password:
            continue
        action = form.get('action') or '/'
        method = (form.get('method') or 'post').lower()
        # ensure absolute action if possible
        # if action is relative, leave as-is; caller should interpret relative to page
        form_result = {'form': form, 'attempts': []}
        attempts = 0
        for user, pwd in credentials:
            if attempts >= max_attempts:
                break
            payload = {}
            for i in inputs:
                name = i.get('name')
                itype = i.get('type', '').lower()
                if not name:
                    continue
                if itype == 'password':
                    payload[name] = pwd
                elif itype in ('text', 'email') and 'user' in name.lower():
                    payload[name] = user
                else:
                    # leave other fields blank or default
                    payload[name] = i.get('value', '')
            try:
                if method == 'post':
                    r = session.post(action, data=payload, headers=REQUEST_HEADERS, timeout=8)
                else:
                    r = session.get(action, params=payload, headers=REQUEST_HEADERS, timeout=8)
                form_result['attempts'].append({'user': user, 'status': r.status_code, 'len': len(r.content)})
            except Exception as e:
                form_result['attempts'].append({'user': user, 'error': str(e)})
            attempts += 1
            time.sleep(delay)
        findings.append(form_result)
    return findings


def detect_login_forms(forms: List[Dict]) -> List[Dict]:
    findings = []
    for form in forms:
        inputs = form.get('inputs', [])
        has_password = any(i.get('type', '').lower() == 'password' for i in inputs)
        method = (form.get('method') or 'get').lower()
        if has_password:
            findings.append({'form': form, 'issue': 'login_form', 'method': method})
    return findings


def robots_check(url: str, session: requests.Session) -> Dict:
    try:
        p = urlparse(url)
        robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
        r = session.get(robots_url, headers=REQUEST_HEADERS, timeout=3)
    except Exception:
        return {}
    if r.status_code == 200 and r.text:
        # Find disallow entries
        disallows = re.findall(r"Disallow:\s*(.*)", r.text, flags=re.I)
        return {'url': robots_url, 'disallows': disallows[:20]}
    return {'url': robots_url, 'status': r.status_code}


def backup_file_check(url: str, session: requests.Session) -> List[Dict]:
    """Check for common backup/config file exposures at the site root using HEAD requests (gentle, passive)."""
    findings = []
    # Reduced to only most critical files
    common = ['.env', 'backup.zip', '.git']
    try:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
    except Exception:
        return findings
    for name in common:
        fu = f"{base}/{name}"
        try:
            r = session.head(fu, headers=REQUEST_HEADERS, timeout=2, allow_redirects=True)
        except Exception:
            continue
        if r.status_code == 200:
            findings.append({'url': fu, 'status': r.status_code})
    return findings


def analyze(pages: List[str], forms: List[Dict], session: requests.Session = None, unsafe: bool = False) -> Dict[str, Any]:
    """Run a collection of passive and optional active checks and return findings."""
    if session is None:
        session = requests.Session()
    findings = {"security_headers": [], "csrf": [], "sensitive": [], "param_pollution": [], "open_redirect": [], "ssrf_lfi_cmd": [], "idor": [], "ssl": [], "cookies": [], "cors": [], "rate_limit": [], "file_uploads": [], "auth": [], "robots": [], "backups": []}

    print(f"  Analyzer: Checking {min(3, len(pages))} pages for security issues...")
    # sample security headers from first 3 pages only (faster)
    for url in pages[:3]:
        try:
            r = session.get(url, headers=REQUEST_HEADERS, timeout=4)
        except Exception:
            continue
        sh = check_security_headers(r)
        if sh.get('issues'):
            findings['security_headers'].append({"url": url, "issues": sh['issues']})
        sfind = detect_sensitive_info(r.text)
        if sfind:
            findings['sensitive'].append({"url": url, "issues": sfind})
        # Skip param pollution test (slow)
        # cookie security
        ck = check_cookie_security(r)
        if ck:
            findings['cookies'].append({"url": url, "issues": ck})
        # CORS passive + active reflection check
        cors_res = check_cors_reflection(url, session)
        if cors_res:
            findings['cors'].append(cors_res)
        # Skip rate-limit test (makes 6 extra requests per URL)
        # robots.txt - only check once for first URL
        if url == pages[0]:
            rchk = robots_check(url, session)
            if rchk:
                findings['robots'].append(rchk)
            # backup files check (passive HEADs) - only check once
            b = backup_file_check(url, session)
            if b:
                findings['backups'].extend(b)

    print(f"  Analyzer: Checking forms...")
    # CSRF checks (forms)
    findings['csrf'] = check_csrf(forms)

    # file upload detection (passive)
    findings['file_uploads'] = detect_file_uploads(forms)

    # login/auth form detection
    findings['auth'] = detect_login_forms(forms)

    # file upload detection (passive)
    findings['file_uploads'] = detect_file_uploads(forms)

    # Skip open redirect (slow, makes extra requests per parameter)
    # Skip IDOR check (slow, makes 2 requests per numeric parameter)
    
    print(f"  Analyzer: Running active tests (unsafe={unsafe})...")
    # SSRF/LFI/CMD tests (active) - gated
    # Only run if unsafe=True (these are very slow)
    if unsafe:
        findings['ssrf_lfi_cmd'] = ssrf_lfi_cmd_tests(pages[:5], session, unsafe=unsafe)

    print(f"  Analyzer: Finalizing...")
    # file upload active tests (very intrusive) - gated behind unsafe
    if unsafe:
        for f in findings.get('file_uploads', [])[:10]:
            form = f.get('form')
            try:
                upload_res = attempt_file_upload(form, session)
            except Exception as e:
                upload_res = {'error': str(e)}
            f['active_test'] = upload_res
        # controlled brute-force login tests (very intrusive) - gated behind unsafe
        try:
            bf = brute_force_login_tests(forms, session, unsafe=unsafe)
            if bf:
                findings['auth_active'] = bf
        except Exception:
            findings['auth_active'] = []

    # Skip SSL check (slow and often times out)
    # hosts = set()
    # for url in pages[:1]:
    #     try:
    #         host = urlparse(url).hostname
    #         if host:
    #             hosts.add(host)
    #     except Exception:
    #         continue
    # for h in hosts:
    #     findings['ssl'].append(ssl_check(h))

    return findings


if __name__ == '__main__':
    import sys
    s = requests.Session()
    print(analyze(sys.argv[1:], [], s, unsafe=False))
"""
Optional analyzer module. Kept minimal for now.
"""

def summarize():
    return None
