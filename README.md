# 🔒 VulnScanner - Automated Web Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

**An educational web vulnerability scanner that automates security testing and generates professional reports**

[Features](#-features) • [How It Works](#-how-it-works) • [Installation](#-installation) • [Usage](#-usage) • [Technology Stack](#-technology-stack)

</div>

---

## 📋 Table of Contents
- [About the Project](#-about-the-project)
- [Why VulnScanner?](#-why-vulnscanner)
- [How It Works](#-how-it-works)
- [Key Features](#-features)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
- [Project Structure](#-project-structure)
- [Technology Stack](#-technology-stack)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🎯 About the Project

**VulnScanner** is an educational web vulnerability scanner built with Python and Flask. It automates the process of discovering security weaknesses in web applications, performing comprehensive security audits, and generating detailed PDF reports.

### What It Does
VulnScanner automatically:
- **Crawls** target websites to discover all pages, links, and forms
- **Tests** for common security vulnerabilities (SQLi, XSS, misconfigurations)
- **Analyzes** security headers, CORS policies, CSRF protection, and cookies
- **Brute-forces** directories to find hidden files and admin panels
- **Generates** professional PDF reports with color-coded severity levels
- **Provides** actionable recommendations to fix vulnerabilities

---

## 🚀 Why VulnScanner?

### Problems It Solves

| Without VulnScanner | With VulnScanner |
|---------------------|------------------|
| ❌ Manual testing takes hours/days | ✅ Automated scan in 2-5 minutes |
| ❌ Inconsistent security checks | ✅ Same comprehensive tests every time |
| ❌ Hard to learn about vulnerabilities | ✅ Educational tool with detailed findings |
| ❌ No documentation for audits | ✅ Auto-generated professional PDF reports |
| ❌ Miss hidden directories/files | ✅ Wordlist-based directory enumeration |
| ❌ Manual header inspection | ✅ Automated security header analysis |

### Who Should Use This?
- 🎓 **Students** learning web security and penetration testing
- 👨‍💻 **Developers** testing their own applications before deployment
- 🔐 **Security Professionals** conducting initial reconnaissance
- 🏆 **Bug Bounty Hunters** looking for quick vulnerability assessments

---

## ⚙️ How It Works

VulnScanner follows a systematic approach to web application security testing:

```
User Input (URL + Settings)
         ↓
    Web Crawler
    (Discovers pages, forms, links)
         ↓
    Vulnerability Scanners
    ├─ SQL Injection Tests
    ├─ XSS Detection
    ├─ Directory Brute-Force
    └─ Security Analysis
         ↓
    Report Generation
    (PDF with findings + recommendations)
         ↓
    Results Display
    (View online or download PDF)
```

### Scanning Process

1. **Crawling Phase** (BFS Algorithm)
   - Starts from the target URL
   - Discovers all internal links up to specified depth
   - Extracts forms with input fields
   - Limits to 50 pages for performance

2. **SQL Injection Testing**
   - Error-based detection (database error messages)
   - Boolean-based blind SQLi (response differential analysis)
   - Tests all forms and URL parameters

3. **Cross-Site Scripting (XSS)**
   - Reflected XSS detection
   - Tests form inputs and URL parameters
   - Checks if payloads appear unescaped in responses

4. **Directory Enumeration**
   - Uses wordlist of common directories (`admin`, `backup`, `config`)
   - Tests multiple file extensions (`.php`, `.html`)
   - Identifies exposed sensitive files

5. **Advanced Security Analysis**
   - **Security Headers**: X-Frame-Options, CSP, HSTS, X-Content-Type-Options
   - **CSRF Protection**: Checks for anti-CSRF tokens in forms
   - **CORS Misconfiguration**: Tests for overly permissive CORS policies
   - **Cookie Security**: Validates Secure and HttpOnly flags
   - **SSRF/LFI/RCE**: Optional unsafe tests for advanced vulnerabilities
   - **Backup Files**: Searches for exposed `.zip`, `.bak`, `.git` files
   - **Open Redirects**: Tests for unvalidated redirect vulnerabilities
   - **IDOR**: Checks for insecure direct object references

6. **Report Generation**
   - Compiles all findings into structured format
   - Assigns severity levels (Critical/High/Medium/Low/Info)
   - Generates color-coded PDF with recommendations
   - Provides HTML view with downloadable report

---

## ✨ Features

### Core Capabilities
- 🕷️ **Intelligent Web Crawler** - BFS-based crawler with depth control and page limiting
- 💉 **SQL Injection Detection** - Error-based and boolean-based blind SQLi detection
- 🚨 **XSS Vulnerability Scanner** - Reflected and stored XSS detection in forms and parameters
- 📁 **Directory Brute-Forcing** - Wordlist-based enumeration with multiple extensions
- 🔍 **Security Header Analysis** - Comprehensive HTTP security header checks
- 🍪 **Cookie Security Audit** - Validates cookie flags and attributes
- 🔐 **CSRF/CORS Testing** - Detects missing CSRF tokens and CORS misconfigurations
- 📊 **Professional PDF Reports** - Color-coded severity tables with executive summaries
- ⚡ **Background Job Processing** - Non-blocking scans with real-time progress updates
- 💾 **Job History** - SQLite database persistence for all scan results

### Advanced Features
- **Session Management** - Connection pooling for 50% faster HTTP requests
- **Progress Tracking** - Real-time updates every 3 seconds during scans
- **Auto-Refresh UI** - Automatic page refresh when jobs are running
- **Consent Modals** - Safety warnings for potentially dangerous tests
- **Detailed Logging** - Step-by-step progress logs for debugging
- **Error Handling** - Graceful handling of network errors and timeouts
- **Responsive Design** - Bootstrap 5 UI works on all devices

### Security Tests Performed

| Category | Tests |
|----------|-------|
| **Injection** | SQL Injection (error-based, blind), Command Injection, LDAP Injection |
| **XSS** | Reflected XSS, Stored XSS (in forms) |
| **Access Control** | IDOR (Insecure Direct Object Reference), Missing CSRF tokens |
| **Security Misconfiguration** | Missing security headers, CORS issues, exposed backup files |
| **SSRF/LFI/RCE** | Server-Side Request Forgery, Local File Inclusion, Remote Code Execution (optional) |
| **Information Disclosure** | Directory listing, backup files (`.git`, `.zip`, `.bak`) |
| **Broken Authentication** | Insecure cookie flags, missing HttpOnly/Secure attributes |

---

## 📦 Installation

### Prerequisites
- **Python 3.10 or higher**
- **pip** (Python package installer)
- **Git** (for cloning the repository)
- **Windows/Linux/macOS**

### Step 1: Clone the Repository

```bash
git clone https://github.com/KartikBansal4976/vulnscanner.git
cd vulnscanner
```

### Step 2: Create Virtual Environment

**On Windows:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies installed:**
- `Flask` - Web framework
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `lxml` - XML/HTML parser
- `reportlab` - PDF generation
- `tqdm` - Progress bars

### Step 4: Run the Application

```bash
python webapp.py
```

The server will start at: **http://127.0.0.1:5000**

### Step 5: Open in Browser

Navigate to `http://127.0.0.1:5000` in your web browser to access the scanner interface.

---

## 📖 Usage Guide

### Basic Workflow

1. **Start the Application**
   ```bash
   cd vulnscanner
   .\.venv\Scripts\Activate.ps1  # Windows
   python webapp.py
   ```

2. **Access Web Interface**
   - Open browser: `http://127.0.0.1:5000`

3. **Configure Scan**
   - **Target URL**: Enter the website to scan (e.g., `http://testphp.vulnweb.com`)
   - **Crawl Depth**: Set how deep to crawl (1-5 levels)
     - Depth 1: Only homepage and direct links
     - Depth 2: Two levels of links (recommended)
     - Depth 3+: More comprehensive but slower
   - **Unsafe Tests**: Enable for SSRF/LFI/RCE tests (requires consent)

4. **Start Scanning**
   - Click "Start Scanning"
   - Page auto-refreshes every 3 seconds
   - Watch progress in "Current Scan Status" card

5. **View Results**
   - Click "View Report" when scan completes
   - See HTML report with all findings
   - Download PDF for professional documentation

### Recommended Test Sites

For learning and testing, use these intentionally vulnerable sites:

- `http://testphp.vulnweb.com` - Designed for security testing
- `http://demo.testfire.net` - Banking demo with vulnerabilities
- `http://www.webscantest.com` - Web scanner test site

**⚠️ NEVER scan sites you don't own without explicit written permission!**

### Understanding Results

**Severity Levels:**
- 🔴 **Critical** - Immediate action required (SQLi, RCE)
- 🟠 **High** - Serious vulnerability (XSS, CSRF)
- 🟡 **Medium** - Should be fixed (Missing headers)
- 🔵 **Low** - Minor issue (Directory listing)
- ⚪ **Info** - Informational (SSL info)

---

## 📂 Project Structure

```
vulnscanner/
│
├── webapp.py                 # Main Flask application & routes
├── storage.py                # SQLite database operations
├── run_scan.py              # CLI scan utility (optional)
├── cleanup_jobs.py          # Database cleanup script
├── requirements.txt         # Python dependencies
├── README.md               # Project documentation
│
├── scanner/                 # Core scanning modules
│   ├── __init__.py
│   ├── crawler.py          # BFS web crawler
│   ├── sqli.py             # SQL injection scanner
│   ├── xss.py              # XSS vulnerability scanner
│   ├── dirbrute.py         # Directory brute-forcer
│   ├── analyzer.py         # Security header/CORS/CSRF analyzer
│   └── reporter.py         # PDF report generator
│
├── templates/              # HTML templates (Jinja2)
│   ├── index.html         # Main scan interface
│   ├── report.html        # Scan results view
│   └── login.html         # Login page (if enabled)
│
├── static/                # Static assets
│   ├── style.css          # Custom CSS styles
│   └── images/            # SVG icons
│       ├── shield.svg
│       ├── lock.svg
│       └── network.svg
│
├── wordlists/             # Directory enumeration wordlists
│   └── common_dirs.txt    # Common directory names
│
├── reports/               # Generated PDF reports (gitignored)
│   └── report_*.pdf
│
└── .venv/                 # Virtual environment (gitignored)
```

### Key Files Explained

| File | Purpose |
|------|---------|
| `webapp.py` | Flask server, routes, background job orchestration |
| `storage.py` | SQLite database CRUD operations for job persistence |
| `scanner/crawler.py` | BFS-based web crawler with depth limiting |
| `scanner/sqli.py` | SQL injection detection (error-based & blind) |
| `scanner/xss.py` | Cross-site scripting vulnerability scanner |
| `scanner/dirbrute.py` | Directory enumeration with wordlist |
| `scanner/analyzer.py` | Advanced security checks (headers, CORS, CSRF, SSRF, LFI) |
| `scanner/reporter.py` | PDF generation with color-coded severity tables |
| `templates/index.html` | Main UI with scan form and job dropdown |
| `templates/report.html` | Results display with findings |

---

## 🛠️ Technology Stack

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.10+ | Core programming language |
| **Flask** | 2.3+ | Web framework for HTTP server and routing |
| **SQLite** | 3 | Lightweight database for job persistence |
| **requests** | Latest | HTTP client with session pooling |
| **BeautifulSoup4** | Latest | HTML/XML parsing for web scraping |
| **lxml** | Latest | Fast XML/HTML parser |
| **ReportLab** | 4.0+ | Professional PDF report generation |
| **tqdm** | Latest | Progress bars for terminal output |

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| **HTML5** | - | Semantic markup |
| **CSS3** | - | Styling and animations |
| **Bootstrap** | 5.3.2 | Responsive UI framework |
| **JavaScript** | ES6+ | Auto-refresh, modals, dynamic updates |
| **AOS** | 2.3.4 | Scroll animations |

### Development Tools
- **Git** - Version control
- **Virtual Environment** - Dependency isolation
- **PowerShell/Bash** - Command-line interface

### Architecture Patterns
- **MVC Pattern** - Flask routes (Controller), Templates (View), Scanner modules (Model)
- **Background Jobs** - Threading for non-blocking scans
- **Session Pooling** - Connection reuse for 50% faster HTTP requests
- **Dual Storage** - In-memory + database for instant UI updates

---

## ⚖️ Legal Disclaimer

**IMPORTANT - READ CAREFULLY BEFORE USE**

This tool is provided for **educational purposes only** and is intended to help security professionals and students learn about web application security.

### Terms of Use

✅ **You MAY use this tool for:**
- Testing your own websites and applications
- Educational purposes in controlled environments
- Authorized penetration testing with written permission
- Security research on intentionally vulnerable test sites

❌ **You MUST NOT use this tool for:**
- Scanning websites without explicit written permission
- Any malicious or illegal activities
- Accessing systems you don't own or have authorization to test
- Any activity that violates local, state, or federal laws

### Legal Notice

- **Unauthorized access** to computer systems is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) in the US and similar legislation worldwide
- The developers assume **no liability** for misuse of this tool
- Users are **solely responsible** for complying with all applicable laws
- Always obtain **written permission** before testing any system you don't own

**By using this tool, you agree to use it legally and ethically.**

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

**Kartik Bansal**
- GitHub: [@KartikBansal4976](https://github.com/KartikBansal4976)
- Email: kartikbansal4976@gmail.com

---

## 🙏 Acknowledgments

- OWASP for vulnerability classification guidelines
- Flask community for excellent documentation
- Security researchers for vulnerability disclosure best practices

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

Made with ❤️ for the security community

</div>
