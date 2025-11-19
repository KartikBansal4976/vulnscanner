"""
Main runner and CLI for the vulnscanner project.

Usage:
    python run_scan.py <target-url> --depth <n> --dirs <path> --report <file>

"""
import argparse
import requests
from scanner import crawler, sqli, xss, dirbrute, reporter
from pathlib import Path
import sys


def parse_args():
    p = argparse.ArgumentParser(description="vulnscanner - simple automated web vulnerability scanner")
    p.add_argument("target", help="Target URL to scan (include http/https)")
    p.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2)")
    p.add_argument("--dirs", default=str(Path(__file__).parent / "wordlists" / "common_dirs.txt"), help="Path to directory wordlist")
    p.add_argument("--report", default=str(Path.cwd() / "vuln_report.pdf"), help="Output PDF report path")
    return p.parse_args()


def main():
    args = parse_args()
    target = args.target
    depth = args.depth
    wordlist_path = args.dirs
    report_path = args.report

    session = requests.Session()

    print(f"Crawling {target} (depth={depth})...")
    pages, forms = crawler.crawl(target, max_depth=depth, session=session)
    print(f"Found {len(pages)} pages and {len(forms)} forms")

    print("Running SQLi checks...")
    sqli_findings = sqli.scan(pages, session=session)
    print(f"SQLi findings: {len(sqli_findings)}")

    print("Running XSS checks...")
    xss_findings = xss.scan(pages, forms, session=session)
    print(f"XSS findings: {len(xss_findings)}")

    print("Running directory brute-force...")
    wl = dirbrute.load_wordlist(wordlist_path)
    dir_findings = dirbrute.probe_paths(target, wl, session=session)
    print(f"Directory findings: {len(dir_findings)}")

    results = {
        "summary": {"target": target, "pages": len(pages)},
        "sqli": sqli_findings,
        "xss": xss_findings,
        "dirs": dir_findings,
        "forms": forms,
    }

    print(f"Generating PDF report at {report_path} ...")
    try:
        reporter.create_pdf(report_path, results)
        print("Report generated.")
    except Exception as e:
        print("Failed to generate report:", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
