"""
Simple Flask frontend + background worker for vulnscanner.

Endpoints:
 - /           GET -> UI with form and job list
 - /start      POST -> start a scan job (returns redirect)
 - /status/<id> GET -> job status JSON
 - /download/<id> GET -> download PDF report when ready

This is intentionally minimal and meant for local use only.
"""
import os
import sys
import threading
import uuid
import time
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, session

from scanner import crawler, sqli, xss, dirbrute, reporter, analyzer
import requests
from storage import init_db, create_job, update_job, get_jobs as storage_get_jobs, get_job as storage_get_job

APP = Flask(__name__)
APP.secret_key = os.environ.get("VULNSCANNER_SECRET", "dev-secret-change-this")
ROOT = Path(__file__).parent
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
DB_PATH = REPORTS_DIR / "jobs.db"
init_db(DB_PATH)

# simple in-memory job store
JOBS = {}


def run_scan_job(job_id: str, target: str, depth: int, wordlist: str, unsafe: bool = False):
    job = JOBS[job_id]
    job["status"] = "running"
    job["started_at"] = time.time()
    try:
        update_job(DB_PATH, job_id, {"status": "running"})
    except Exception as e:
        print(f"[{job_id[:8]}] DB update error: {e}")
    
    try:
        # Use a shared session for connection pooling (faster)
        session = requests.Session()
        print(f"[{job_id[:8]}] Starting crawl...")
        sys.stdout.flush()
        # Limit to 50 pages max to prevent huge sites from taking forever
        pages, forms = crawler.crawl(target, max_depth=depth, session=session, max_pages=50)
        job["pages_found"] = len(pages)
        job["forms_found"] = len(forms)
        print(f"[{job_id[:8]}] Found {len(pages)} pages, {len(forms)} forms")

        print(f"[{job_id[:8]}] Running SQLi scan...")
        sqli_findings = sqli.scan(pages, session=session)
        print(f"[{job_id[:8]}] SQLi complete: {len(sqli_findings)} findings")

        print(f"[{job_id[:8]}] Running XSS scan...")
        xss_findings = xss.scan(pages, forms, session=session)
        print(f"[{job_id[:8]}] XSS complete: {len(xss_findings)} findings")

        print(f"[{job_id[:8]}] Running directory brute-force...")
        wl = dirbrute.load_wordlist(wordlist)
        # Use full wordlist for comprehensive scans
        dir_findings = dirbrute.probe_paths(target, wl, session=session)
        print(f"[{job_id[:8]}] Dirbrute complete: {len(dir_findings)} findings")

        # analyzer: passive checks + optional active tests (gated by unsafe)
        print(f"[{job_id[:8]}] Running analyzer...")
        try:
            analyzer_findings = analyzer.analyze(pages, forms, session=session, unsafe=bool(job.get('unsafe', False)))
            print(f"[{job_id[:8]}] Analyzer complete")
        except Exception as e:
            print(f"[{job_id[:8]}] Analyzer error: {e}")
            analyzer_findings = {"error": str(e)}

        print(f"[{job_id[:8]}] Generating report...")
        report_path = REPORTS_DIR / f"report_{job_id}.pdf"
        results = {
            "summary": {"target": target, "pages": len(pages)},
            "sqli": sqli_findings,
            "xss": xss_findings,
            "dirs": dir_findings,
            "forms": forms,
            "analyzer": analyzer_findings,
        }
        # attach human-friendly suggestions and save results with job
        results["suggestions"] = generate_suggestions(results)
        print(f"[{job_id[:8]}] Creating PDF...")
        reporter.create_pdf(str(report_path), results)
        print(f"[{job_id[:8]}] Scan complete!")
        job["status"] = "done"
        job["report"] = str(report_path.name)
        job["results"] = results
        try:
            update_job(DB_PATH, job_id, {"status": "done", "report": job["report"], "results": results})
        except Exception:
            pass
    except Exception as e:
        print(f"[{job_id[:8]}] SCAN FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        job["status"] = "failed"
        job["error"] = str(e)
        try:
            update_job(DB_PATH, job_id, {"status": "failed"})
        except Exception as db_err:
            print(f"[{job_id[:8]}] DB update error: {db_err}")
    finally:
        job["finished_at"] = time.time()


@APP.route("/", methods=["GET"]) 
def index():
    # Merge in-memory jobs with stored jobs for real-time updates
    try:
        stored = storage_get_jobs(DB_PATH)
    except Exception:
        stored = []
    
    # Update stored jobs with in-memory status if available (more current)
    jobs_dict = {}
    for job in stored:
        job_id = job["id"]
        # If job is in memory, use its status (more up-to-date)
        if job_id in JOBS:
            job["status"] = JOBS[job_id].get("status", job.get("status"))
            job["pages_found"] = JOBS[job_id].get("pages_found", job.get("pages_found"))
            job["forms_found"] = JOBS[job_id].get("forms_found", job.get("forms_found"))
        jobs_dict[job_id] = job
    
    jobs_list = [(job_id, job) for job_id, job in jobs_dict.items()]
    # Sort by created_at descending
    jobs_list.sort(key=lambda x: x[1].get("created_at", 0), reverse=True)
    
    user = session.get("user")
    return render_template("index.html", jobs=jobs_list, user=user)


@APP.route("/start", methods=["POST"])
def start():
    target = request.form.get("target")
    depth = int(request.form.get("depth") or 1)
    wl = request.form.get("wordlist") or str(ROOT / "wordlists" / "common_dirs.txt")
    unsafe = request.form.get('unsafe') == 'on'
    job_id = uuid.uuid4().hex
    # allow anonymous scans; store user if present
    job = {"id": job_id, "target": target, "depth": depth, "created_at": time.time(), "status": "queued", "user": session.get("user") or "anonymous", "unsafe": unsafe}
    JOBS[job_id] = job
    try:
        create_job(DB_PATH, job)
    except Exception:
        pass
    t = threading.Thread(target=run_scan_job, args=(job_id, target, depth, wl, unsafe), daemon=True)
    t.start()
    return redirect(url_for("index"))


@APP.route("/status/<job_id>")
def status(job_id):
    # Try in-memory first (real-time), then database
    job = JOBS.get(job_id)
    if not job:
        # Try loading from database
        try:
            job = storage_get_job(DB_PATH, job_id)
        except Exception:
            pass
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job)


@APP.route("/download/<job_id>")
def download(job_id):
    # Try in-memory first, then database
    job = JOBS.get(job_id)
    if not job:
        try:
            job = storage_get_job(DB_PATH, job_id)
        except Exception:
            pass
    if not job:
        return "Unknown job", 404
    if job.get("status") != "done":
        return "Report not ready", 404
    filename = job.get("report")
    return send_from_directory(str(REPORTS_DIR), filename, as_attachment=True)





@APP.route('/report/<job_id>')
def report_view(job_id):
    # Try in-memory first, then database
    job = JOBS.get(job_id)
    if not job:
        try:
            job = storage_get_job(DB_PATH, job_id)
        except Exception:
            pass
    if not job:
        return "Unknown job", 404
    results = job.get('results')
    return render_template('report.html', job=job, results=results)


def generate_suggestions(results: dict) -> dict:
    """Produce basic remediation suggestions for detected issues.

    This is a simple rule-based helper mapping findings to actionable text.
    """
    suggestions = {"sqli": [], "xss": [], "dirs": [], "forms": []}
    for f in results.get('sqli', []):
        param = f.get('param')
        suggestions['sqli'].append({
            'issue': f"Possible SQL Injection on parameter '{param}' (type: {f.get('type')})",
            'recommendation': 'Use parameterized queries / prepared statements, validate and whitelist input, and apply least privilege to DB accounts.'
        })
    for x in results.get('xss', []):
        param = x.get('param') or x.get('form', {}).get('action')
        suggestions['xss'].append({
            'issue': f"Reflected XSS possible in '{param}'",
            'recommendation': 'Escape output context-sensitively, use Content-Security-Policy, and validate/encode inputs.'
        })
    for d in results.get('dirs', []):
        suggestions['dirs'].append({
            'issue': f"Discoverable path: {d.get('url')} (status {d.get('status')})",
            'recommendation': 'Remove sensitive files from webroot, harden file permissions, and disable directory listing.'
        })
    for form in results.get('forms', []):
        suggestions['forms'].append({
            'issue': f"Form found: action={form.get('action')} method={form.get('method')}",
            'recommendation': 'Ensure forms use CSRF tokens, validate inputs server-side, and avoid reflecting raw input back to pages.'
        })
    # analyzer suggestions
    analy = results.get('analyzer', {}) or {}
    # cookies
    for c in analy.get('cookies', []):
        for ck in c.get('issues', []):
            suggestions.setdefault('analyzer_cookies', []).append({
                'issue': f"Cookie {ck.get('cookie')} missing flags: {', '.join(ck.get('missing_flags', []))}",
                'recommendation': 'Set Secure, HttpOnly and SameSite attributes on cookies; use secure session storage.'
            })
    # cors
    for co in analy.get('cors', []):
        if co.get('issue') == 'cors_reflect' or co.get('acao') == '*':
            suggestions.setdefault('analyzer_cors', []).append({
                'issue': f"CORS misconfiguration: {co.get('value') or co.get('acao')}",
                'recommendation': 'Only allow trusted origins in Access-Control-Allow-Origin and avoid reflecting the Origin header.'
            })
    # rate limit
    for rl in analy.get('rate_limit', []):
        if rl.get('429_seen') or rl.get('throttling_suspected'):
            suggestions.setdefault('analyzer_rate_limit', []).append({
                'issue': f"Rate limiting observed or suspected on {rl.get('url')}",
                'recommendation': 'Implement consistent rate-limiting and throttling policies; return 429 for abusive clients.'
            })
    # robots
    for r in analy.get('robots', []):
        if r.get('disallows'):
            suggestions.setdefault('analyzer_robots', []).append({
                'issue': f"robots.txt disallows present: {len(r.get('disallows'))} entries",
                'recommendation': 'Review disallowed paths; do not rely on robots.txt for security and avoid exposing sensitive paths via public files.'
            })
    # backups
    for b in analy.get('backups', []):
        suggestions.setdefault('analyzer_backups', []).append({
            'issue': f"Exposed backup/config file: {b.get('url')}",
            'recommendation': 'Remove backup and config files from webroot and restrict access to configuration files.'
        })
    # auth forms
    for a in analy.get('auth', []):
        suggestions.setdefault('analyzer_auth', []).append({
            'issue': f"Login form detected at {a.get('form', {}).get('action')}",
            'recommendation': 'Ensure login endpoints implement brute-force protections, rate limiting and secure cookies; use MFA where possible.'
        })
    # active auth tests
    for af in analy.get('auth_active', []):
        # summarize attempts
        attempts = af.get('attempts', [])
        positive = [at for at in attempts if at.get('status') and at.get('status') < 400]
        if positive:
            suggestions.setdefault('analyzer_auth_active', []).append({
                'issue': f"Successful login attempt observed for form {af.get('form', {}).get('action')}",
                'recommendation': 'Investigate credentials used and ensure accounts are secured; add rate-limiting, account lockouts and MFA.'
            })
    return suggestions


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000, debug=True)
