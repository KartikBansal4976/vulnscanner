# vulnscanner

vulnscanner is a simple, synchronous automated web vulnerability scanner demo implemented in Python 3.10+. It is intended for educational and authorized use only.

Features
- Crawl pages within the same domain (BFS)
- Detect GET parameters and HTML forms
- SQL Injection detection (error-based, boolean-differential, length heuristics)
- XSS detection (reflected) with multiple payloads
- Directory brute-force using a wordlist
- Generate a clean PDF report summarizing findings
- CLI using argparse

Installation
1. Create a Python 3.10+ virtual environment and activate it.
2. Install dependencies:

```
pip install -r requirements.txt
```

Usage

```
python run_scan.py https://example.com --depth 2 --dirs wordlists/common_dirs.txt --report vuln_report.pdf
```

Web UI

You can also run a small web frontend that lets you start scans from your browser and download PDF reports.

1. Activate your venv (see above).
2. Start the web app:

```powershell
python webapp.py
```

3. Open http://127.0.0.1:5000 in your browser.

Legal disclaimer

Only scan websites you own or have explicit permission to test. Unauthorized scanning may be illegal and unethical.

Notes
- This is a simple educational tool. It does not replace full-featured scanners and may produce false positives or negatives.
- Use responsibly.
