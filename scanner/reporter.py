"""
PDF reporting using reportlab. Summarizes SQLi, XSS, dirbrute, forms, and analyzer findings.
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from typing import Dict, List


def create_pdf(path: str, results: Dict):
    doc = SimpleDocTemplate(path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    elems = []
    
    # Title
    title = Paragraph("VulnScanner Security Report", styles["Title"])
    elems.append(title)
    elems.append(Spacer(1, 12))

    # Summary
    elems.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary = results.get("summary", {})
    elems.append(Paragraph(f"<b>Target:</b> {summary.get('target', 'N/A')}", styles["Normal"]))
    elems.append(Paragraph(f"<b>Pages scanned:</b> {summary.get('pages', 0)}", styles["Normal"]))
    
    # Count findings
    sqli_count = len(results.get("sqli", []))
    xss_count = len(results.get("xss", []))
    dir_count = len(results.get("dirs", []))
    analyzer = results.get("analyzer", {})
    
    elems.append(Spacer(1, 6))
    elems.append(Paragraph(f"<b>Critical Findings:</b>", styles["Normal"]))
    elems.append(Paragraph(f"• SQL Injection: {sqli_count}", styles["Normal"]))
    elems.append(Paragraph(f"• XSS: {xss_count}", styles["Normal"]))
    elems.append(Paragraph(f"• Directory Exposure: {dir_count}", styles["Normal"]))
    elems.append(Paragraph(f"• Security Headers Issues: {len(analyzer.get('security_headers', []))}", styles["Normal"]))
    elems.append(Paragraph(f"• CORS Issues: {len(analyzer.get('cors', []))}", styles["Normal"]))
    elems.append(Paragraph(f"• CSRF Issues: {len(analyzer.get('csrf', []))}", styles["Normal"]))
    elems.append(Spacer(1, 12))

    # SQLi
    elems.append(Paragraph("SQL Injection Findings", styles["Heading2"]))
    sqli = results.get("sqli", [])
    if not sqli:
        elems.append(Paragraph("✓ No SQLi vulnerabilities found.", styles["Normal"]))
    else:
        data = [["URL", "Parameter", "Type", "Evidence"]]
        for f in sqli:
            url_short = f.get("url", "")[:40] + "..." if len(f.get("url", "")) > 40 else f.get("url", "")
            data.append([url_short, f.get("param"), f.get("type"), str(f.get("evidence"))[:50]])
        t = Table(data, colWidths=[140, 80, 80, 160])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.red),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elems.append(t)
    elems.append(Spacer(1, 12))

    # XSS
    elems.append(Paragraph("Cross-Site Scripting (XSS) Findings", styles["Heading2"]))
    xss = results.get("xss", [])
    if not xss:
        elems.append(Paragraph("✓ No XSS vulnerabilities found.", styles["Normal"]))
    else:
        data = [["URL/Parameter", "Payload", "Evidence Snippet"]]
        for f in xss:
            name = f.get("url") or f.get("form", {}).get("action")
            name_short = name[:40] + "..." if len(name) > 40 else name
            payload_short = f.get("payload", "")[:30]
            data.append([name_short, payload_short, (f.get("evidence_snippet") or "")[:60]])
        t = Table(data, colWidths=[160, 120, 180])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.orange),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elems.append(t)
    elems.append(Spacer(1, 12))

    # Dirbrute
    elems.append(Paragraph("Directory & File Exposure", styles["Heading2"]))
    dirs = results.get("dirs", [])
    if not dirs:
        elems.append(Paragraph("✓ No exposed directories found.", styles["Normal"]))
    else:
        elems.append(Paragraph(f"Found {len(dirs)} exposed paths:", styles["Normal"]))
        data = [["URL", "Status", "Size"]]
        for d in dirs[:30]:  # Limit to first 30 for PDF space
            url_short = d.get("url", "")[:60] + "..." if len(d.get("url", "")) > 60 else d.get("url", "")
            data.append([url_short, str(d.get("status")), str(d.get("length"))])
        t = Table(data, colWidths=[340, 60, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elems.append(t)
        if len(dirs) > 30:
            elems.append(Paragraph(f"... and {len(dirs) - 30} more paths.", styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Page break before analyzer section
    elems.append(PageBreak())
    
    # Analyzer Findings
    elems.append(Paragraph("Advanced Security Analysis", styles["Heading1"]))
    elems.append(Spacer(1, 12))
    
    # Security Headers
    elems.append(Paragraph("Security Headers Analysis", styles["Heading2"]))
    sec_headers = analyzer.get('security_headers', [])
    if not sec_headers:
        elems.append(Paragraph("✓ No security header issues detected.", styles["Normal"]))
    else:
        for sh in sec_headers[:5]:
            elems.append(Paragraph(f"<b>URL:</b> {sh.get('url', '')[:70]}", styles["Normal"]))
            for issue in sh.get('issues', []):
                elems.append(Paragraph(f"  • {issue}", styles["Normal"]))
            elems.append(Spacer(1, 6))
    elems.append(Spacer(1, 12))

    # CORS Issues
    elems.append(Paragraph("CORS (Cross-Origin Resource Sharing)", styles["Heading2"]))
    cors_issues = analyzer.get('cors', [])
    if not cors_issues:
        elems.append(Paragraph("✓ No CORS issues detected.", styles["Normal"]))
    else:
        for c in cors_issues[:5]:
            elems.append(Paragraph(f"<b>URL:</b> {c.get('url', '')[:70]}", styles["Normal"]))
            if c.get('issue'):
                elems.append(Paragraph(f"  Issue: {c.get('issue')} - {c.get('value', c.get('acao', ''))}", styles["Normal"]))
            elems.append(Spacer(1, 6))
    elems.append(Spacer(1, 12))

    # CSRF Issues
    elems.append(Paragraph("CSRF (Cross-Site Request Forgery)", styles["Heading2"]))
    csrf_issues = analyzer.get('csrf', [])
    if not csrf_issues:
        elems.append(Paragraph("✓ All forms have CSRF protection.", styles["Normal"]))
    else:
        elems.append(Paragraph(f"Found {len(csrf_issues)} forms without CSRF tokens:", styles["Normal"]))
        for cf in csrf_issues[:10]:
            form = cf.get('form', {})
            elems.append(Paragraph(f"  • Form action: {form.get('action', 'N/A')[:60]}", styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Cookie Security
    elems.append(Paragraph("Cookie Security", styles["Heading2"]))
    cookie_issues = analyzer.get('cookies', [])
    if not cookie_issues:
        elems.append(Paragraph("✓ No cookie security issues detected.", styles["Normal"]))
    else:
        for ck in cookie_issues[:5]:
            elems.append(Paragraph(f"<b>URL:</b> {ck.get('url', '')[:70]}", styles["Normal"]))
            for cookie in ck.get('issues', []):
                elems.append(Paragraph(f"  • Cookie '{cookie.get('cookie')}' missing: {', '.join(cookie.get('missing_flags', []))}", styles["Normal"]))
            elems.append(Spacer(1, 6))
    elems.append(Spacer(1, 12))

    # Backup Files
    elems.append(Paragraph("Exposed Backup/Config Files", styles["Heading2"]))
    backups = analyzer.get('backups', [])
    if not backups:
        elems.append(Paragraph("✓ No exposed backup files detected.", styles["Normal"]))
    else:
        elems.append(Paragraph("<b>⚠ WARNING: Sensitive files exposed!</b>", styles["Normal"]))
        for b in backups:
            elems.append(Paragraph(f"  • {b.get('url')} (Status: {b.get('status')})", styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Sensitive Info
    elems.append(Paragraph("Sensitive Information Exposure", styles["Heading2"]))
    sensitive = analyzer.get('sensitive', [])
    if not sensitive:
        elems.append(Paragraph("✓ No sensitive information detected in responses.", styles["Normal"]))
    else:
        for s in sensitive[:5]:
            elems.append(Paragraph(f"<b>URL:</b> {s.get('url', '')[:70]}", styles["Normal"]))
            for issue in s.get('issues', []):
                elems.append(Paragraph(f"  • {issue.get('type')}: {issue.get('evidence')}", styles["Normal"]))
            elems.append(Spacer(1, 6))
    elems.append(Spacer(1, 12))

    # SSRF/LFI/CMD (if unsafe was enabled)
    ssrf_lfi_cmd = analyzer.get('ssrf_lfi_cmd', [])
    if ssrf_lfi_cmd:
        elems.append(Paragraph("Critical: SSRF/LFI/Command Injection", styles["Heading2"]))
        for finding in ssrf_lfi_cmd[:10]:
            elems.append(Paragraph(f"<b>Type:</b> {finding.get('type').upper()}", styles["Normal"]))
            elems.append(Paragraph(f"<b>URL:</b> {finding.get('url', '')[:60]}", styles["Normal"]))
            elems.append(Paragraph(f"<b>Parameter:</b> {finding.get('param')}", styles["Normal"]))
            elems.append(Paragraph(f"<b>Payload:</b> {finding.get('payload', '')[:60]}", styles["Normal"]))
            elems.append(Spacer(1, 8))
    
    # Forms
    elems.append(PageBreak())
    elems.append(Paragraph("Discovered Forms", styles["Heading2"]))
    forms = results.get("forms", [])
    if not forms:
        elems.append(Paragraph("No forms discovered.", styles["Normal"]))
    else:
        for form in forms[:20]:
            elems.append(Paragraph(f"<b>Action:</b> {form.get('action')} | <b>Method:</b> {form.get('method')}", styles["Normal"]))
            inputs = form.get("inputs", [])
            if inputs:
                input_names = ", ".join(i.get('name', '') for i in inputs[:10])
                elems.append(Paragraph(f"Inputs: {input_names}", styles["Normal"]))
            elems.append(Spacer(1, 6))

    # Recommendations
    elems.append(PageBreak())
    elems.append(Paragraph("Security Recommendations", styles["Heading1"]))
    elems.append(Spacer(1, 12))
    
    suggestions = results.get('suggestions', {})
    if suggestions:
        for category, items in suggestions.items():
            if items and len(items) > 0:
                elems.append(Paragraph(f"{category.upper().replace('_', ' ')}", styles["Heading2"]))
                for item in items[:5]:  # Limit to 5 per category
                    elems.append(Paragraph(f"<b>Issue:</b> {item.get('issue', '')[:100]}", styles["Normal"]))
                    elems.append(Paragraph(f"<b>Fix:</b> {item.get('recommendation', '')[:200]}", styles["Normal"]))
                    elems.append(Spacer(1, 8))
                elems.append(Spacer(1, 12))

    doc.build(elems)


if __name__ == "__main__":
    # quick local smoke test: create an empty report
    create_pdf("vuln_report_sample.pdf", {"summary": {"target": "none", "pages": 0}, "sqli": [], "xss": [], "dirs": [], "forms": [], "analyzer": {}})
