"""
SafeScan Pro PDF Security Report Generator
Comprehensive, non-technical-friendly security report.
"""
import os
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors as C
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle, HRFlowable, Image,
                                PageBreak, KeepTogether)
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ── Colors ────────────────────────────────────────────────────────────────────
BG_DARK   = C.HexColor("#0d1117")
BG_LIGHT  = C.HexColor("#f6f8fa")
BORDER    = C.HexColor("#d0d7de")
BLUE      = C.HexColor("#0969da")
GREY_TEXT = C.HexColor("#656d76")
VCOLORS   = {"SAFE": C.green, "SUSPICIOUS": C.orange, "DANGEROUS": C.red}

# ── Explanation texts for non-technical users ─────────────────────────────────
EXPLANATIONS = {
    "summary": "This report summarises the security analysis of a scanned QR code or URL. "
               "The verdict tells you whether it is safe to use. A higher risk score means greater danger.",
    "score_breakdown": "Each signal below is an independent security check. "
                       "The points show how much risk each check found. All signals add up to the Total Risk Score out of 100.",
    "domain": "A domain is the website address (e.g. google.com). "
              "New domains (less than 30 days old) are often used by scammers because they are cheap and disposable.",
    "ml": "Our AI model analyses the URL pattern to detect phishing. "
          "If the URL looks similar to known scam links, it is flagged. Higher confidence means the AI is more certain.",
    "gsb": "Google maintains a live database of dangerous websites. "
           "If a URL appears in this database, it has been confirmed as malicious by Google's security team.",
    "vt": "VirusTotal checks the URL against 70+ antivirus engines worldwide. "
          "If multiple engines flag the URL, it is very likely dangerous.",
    "ssl": "SSL (the padlock icon in your browser) encrypts your connection. "
           "Missing or expired SSL means your data could be intercepted. Free SSL on a new domain is a common scam tactic.",
    "headers": "Security headers are invisible settings that protect you from attacks. "
               "A low score means the website owner has not configured basic protections.",
    "dns": "DNS translates a website name into a server address. "
           "This section shows where the website is physically hosted and whether it uses a CDN (content delivery network).",
    "page": "We analyse the actual webpage content for suspicious patterns like hidden login forms, "
            "obfuscated code, and phishing keywords (e.g. 'verify your account', 'urgent action required').",
    "sandbox": "We opened the URL in a secure isolated environment (sandbox) to observe its behaviour. "
               "This detects malware that only activates when a real user visits the page.",
    "upi": "UPI (Unified Payments Interface) is India's instant payment system. "
           "This section shows who would receive your money and whether the payment details look suspicious.",
    "bank": "This shows which bank processes the payment. "
            "The information is derived from the UPI handle (the part after @).",
    "fraud": "These are specific warning signs detected in the QR code. "
             "Each signal is an independent indicator of potential fraud. HIGH severity means serious risk.",
    "forensic": "The forensic evidence section contains technical details collected during the scan. "
                "This information can be shared with law enforcement (cybercrime.gov.in) if you are a victim.",
    "redirects": "Redirects are when a URL sends you to a different website automatically. "
                 "Scammers use multiple redirects to hide the real destination.",
    "prevention": "Based on the analysis, we have taken automatic action to protect you. "
                  "Blocked means the QR code was prevented from executing.",
}


def generate_report(data: dict) -> BytesIO:
    """Generate a comprehensive SafeScan Pro security report PDF."""
    verdict  = (data.get("verdict") or "UNKNOWN").upper()
    target   = data.get("url") or data.get("qr_data") or "Unknown"
    qr_type  = (data.get("qr_type") or "URL").upper()
    risk     = data.get("risk_score", "N/A")
    ts       = data.get("time", datetime.utcnow().isoformat())
    analysis = data.get("analysis", {})
    upi      = data.get("upi_analysis") or data.get("parsed_data") or {}
    breakdown = data.get("score_breakdown", [])
    forensic = data.get("forensic_evidence", {})
    vc       = VCOLORS.get(verdict, C.grey)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=1.5*cm, bottomMargin=1.5*cm)
    ss    = getSampleStyleSheet()
    story = []

    # ── Styles ────────────────────────────────────────────────────────────
    title_s = ParagraphStyle("rptTitle", parent=ss["Title"], fontSize=22,
                             textColor=BLUE, spaceAfter=4, alignment=TA_CENTER)
    sub_s   = ParagraphStyle("rptSub", parent=ss["Normal"], fontSize=10,
                             textColor=GREY_TEXT, alignment=TA_CENTER, spaceAfter=2)
    h2_s    = ParagraphStyle("rptH2", parent=ss["Heading2"], fontSize=13,
                             textColor=BLUE, spaceBefore=14, spaceAfter=4)
    explain_s = ParagraphStyle("rptExplain", parent=ss["Normal"], fontSize=8,
                               textColor=GREY_TEXT, spaceAfter=6,
                               leftIndent=6, rightIndent=6)
    normal_s = ParagraphStyle("rptNormal", parent=ss["Normal"], fontSize=9)

    # ── Helper functions ──────────────────────────────────────────────────
    def section(title, explain_key=None):
        story.append(Paragraph(title, h2_s))
        story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=4))
        if explain_key and explain_key in EXPLANATIONS:
            story.append(Paragraph(EXPLANATIONS[explain_key], explain_s))

    def rows(data_list):
        if not data_list:
            return
        tbl = Table(data_list, colWidths=[5*cm, 12*cm])
        tbl.setStyle(TableStyle([
            ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("TEXTCOLOR",      (0,0), (0,-1),  GREY_TEXT),
            ("GRID",           (0,0), (-1,-1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C.white, BG_LIGHT]),
            ("PADDING",        (0,0), (-1,-1), 6),
            ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ]))
        story.append(tbl)

    def safe_str(v, fallback="N/A"):
        if v is None or v == "":
            return fallback
        return str(v)[:120]

    # ══════════════════════════════════════════════════════════════════════
    #  PAGE 1: TITLE PAGE WITH LOGO (Brand-First Design)
    # ══════════════════════════════════════════════════════════════════════
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "static", "safescan_logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join("static", "safescan_logo.png")

    story.append(Spacer(1, 2.5*cm))

    if os.path.exists(logo_path):
        try:
            # Logo is the primary brand — large and centered
            logo = Image(logo_path, width=14*cm, height=4.5*cm,
                         kind='proportional')
            logo.hAlign = "CENTER"
            story.append(logo)
        except Exception:
            # Fallback: text-only brand
            story.append(Paragraph("SafeScan Pro", title_s))
    else:
        story.append(Paragraph("SafeScan Pro", title_s))

    story.append(Spacer(1, 0.6*cm))
    # Thin brand-color separator
    story.append(HRFlowable(width="40%", thickness=2,
                            color=C.HexColor("#2B7BC4"), spaceAfter=8))
    # Subtitle — "Security Report" only (logo already has the brand name)
    report_sub = ParagraphStyle("rptSub2", parent=ss["Title"], fontSize=18,
                                textColor=BG_DARK, alignment=TA_CENTER, spaceAfter=4)
    story.append(Paragraph("Security Report", report_sub))
    story.append(Spacer(1, 0.4*cm))

    # Verdict banner
    verdict_banner = Table(
        [[verdict]],
        colWidths=[8*cm], rowHeights=[1.2*cm]
    )
    verdict_banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), vc),
        ("TEXTCOLOR",  (0,0), (-1,-1), C.white),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 18),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ROUNDEDCORNERS", [6,6,6,6]),
    ]))
    verdict_banner.hAlign = "CENTER"
    story.append(verdict_banner)
    story.append(Spacer(1, 0.5*cm))

    # Summary table
    summary = [
        ["Risk Score",  f"{risk}%" if risk != "N/A" else "N/A"],
        ["QR Type",     qr_type],
        ["Target",      safe_str(target, "Unknown")[:80]],
        ["Scan Time",   ts[:19].replace("T", " ")],
        ["Report Date", datetime.utcnow().strftime("%d %b %Y %H:%M UTC")],
    ]
    st = Table(summary, colWidths=[4*cm, 13*cm])
    st.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1),  BG_DARK),
        ("TEXTCOLOR",     (0,0), (0,-1),  C.white),
        ("FONTNAME",      (0,0), (-1,-1), "Helvetica"),
        ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("GRID",          (0,0), (-1,-1), 0.5, BORDER),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [C.white, BG_LIGHT]),
        ("PADDING",       (0,0), (-1,-1), 8),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(EXPLANATIONS["summary"], explain_s))

    # ══════════════════════════════════════════════════════════════════════
    #  SCORE BREAKDOWN
    # ══════════════════════════════════════════════════════════════════════
    if breakdown:
        story.append(PageBreak())
        section("Risk Score Breakdown", "score_breakdown")
        bd_rows = [["Signal", "Points", "Max", "Status", "Detail"]]
        for b in breakdown:
            bd_rows.append([
                safe_str(b.get("signal")),
                str(b.get("points", 0)),
                str(b.get("max", 0)),
                safe_str(b.get("status")),
                safe_str(b.get("detail"))[:70],
            ])
        bd_rows.append(["Total Risk Score", str(risk), "100", verdict, ""])
        bd_tbl = Table(bd_rows, colWidths=[3.8*cm, 1.5*cm, 1.2*cm, 2*cm, 8.5*cm])
        bd_style = [
            ("BACKGROUND",    (0,0), (-1,0),  BG_DARK),
            ("TEXTCOLOR",     (0,0), (-1,0),  C.white),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.3, BORDER),
            ("ROWBACKGROUNDS",(0,1), (-1,-2), [C.white, BG_LIGHT]),
            ("BACKGROUND",    (0,-1),(- 1,-1), BG_DARK),
            ("TEXTCOLOR",     (0,-1),(-1,-1), C.white),
            ("FONTNAME",      (0,-1),(-1,-1), "Helvetica-Bold"),
            ("PADDING",       (0,0), (-1,-1), 5),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]
        # Color status cells
        for i, b in enumerate(breakdown, 1):
            st_val = (b.get("status") or "").upper()
            if st_val == "THREAT":
                bd_style.append(("TEXTCOLOR", (3,i), (3,i), C.red))
            elif st_val == "WARN":
                bd_style.append(("TEXTCOLOR", (3,i), (3,i), C.orange))
            elif st_val == "SAFE":
                bd_style.append(("TEXTCOLOR", (3,i), (3,i), C.green))
        bd_tbl.setStyle(TableStyle(bd_style))
        story.append(bd_tbl)

    # ══════════════════════════════════════════════════════════════════════
    #  URL ANALYSIS SECTIONS
    # ══════════════════════════════════════════════════════════════════════
    if qr_type == "URL" and analysis:
        # Domain
        if analysis.get("domain"):
            dm = analysis["domain"]
            section("Domain Analysis", "domain")
            rows([["Domain",     safe_str(dm.get("domain"))],
                  ["Registrar",  safe_str(dm.get("registrar"))],
                  ["Age",        f"{dm.get('age_days', 'Unknown')} days"],
                  ["New Domain", "Yes - WARNING" if dm.get("is_new") else "No - Established"],
                  ["Created",    safe_str(dm.get("creation_date"))],
                  ["Expires",    safe_str(dm.get("expiry_date"))]])

        # ML
        if analysis.get("ml"):
            ml = analysis["ml"]
            section("ML Phishing Detection", "ml")
            result_text = "PHISHING DETECTED" if ml.get("is_phishing") else "Clean - No phishing detected"
            rows([["Result",     result_text],
                  ["Confidence", f"{ml.get('confidence', 0)}%"],
                  ["What it means",
                   "Our AI believes this URL matches phishing patterns." if ml.get("is_phishing")
                   else "Our AI did not find phishing patterns in this URL."]])

        # GSB
        if analysis.get("google_safe_browsing"):
            gsb = analysis["google_safe_browsing"]
            section("Google Safe Browsing", "gsb")
            is_safe = gsb.get("is_safe", True)
            rows([["Status", "SAFE - Not in Google's threat database" if is_safe
                   else "UNSAFE - Confirmed threat by Google"],
                  ["What it means",
                   "Google has not flagged this URL." if is_safe
                   else "Google has confirmed this URL is dangerous. Do NOT visit it."]])

        # VirusTotal
        if analysis.get("virustotal"):
            vt = analysis["virustotal"]
            section("VirusTotal (70+ Engines)", "vt")
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            rows([["Malicious Engines",  str(mal)],
                  ["Suspicious Engines", str(sus)],
                  ["Risk Percentage",    f"{vt.get('risk_percentage', 0):.1f}%"],
                  ["What it means",
                   f"{mal} out of 70+ antivirus engines flagged this URL as dangerous."
                   if mal > 0 else "No antivirus engine flagged this URL."]])

        # SSL
        if analysis.get("ssl"):
            sl = analysis["ssl"]
            section("SSL Certificate", "ssl")
            status = ("Expired - DANGER" if sl.get("is_expired")
                      else "Expiring Soon" if sl.get("is_expiring_soon") else "Valid")
            rows([["Has SSL",     "Yes (Encrypted)" if sl.get("has_ssl") else "No - DANGER"],
                  ["Issuer",      safe_str(sl.get("issuer"))],
                  ["Days Left",   safe_str(sl.get("days_until_expiry"))],
                  ["Status",      status],
                  ["What it means",
                   "Your connection to this site is encrypted." if sl.get("has_ssl")
                   else "This site has NO encryption. Your data can be intercepted."]])

        # HTTP Headers
        if analysis.get("http_headers"):
            hh = analysis["http_headers"]
            section("HTTP Security Headers", "headers")
            rows([["Security Grade", safe_str(hh.get("grade"))],
                  ["Score",          f"{hh.get('score', 0)}%"],
                  ["Headers Found",  f"{hh.get('found_count', 0)} / {hh.get('total_checked', 7)}"],
                  ["Server",         safe_str(hh.get("server"))]])

        # DNS
        if analysis.get("dns"):
            dns = analysis["dns"]
            section("DNS & Infrastructure", "dns")
            ips = ", ".join(dns.get("ip_addresses", [])[:3]) or "N/A"
            rows([["Hostname",    safe_str(dns.get("hostname"))],
                  ["IP Address",  ips],
                  ["CDN",         dns.get("cdn_provider") or ("Detected" if dns.get("cdn_detected") else "None")],
                  ["Multiple IPs", str(dns.get("multiple_ips", False))]])

        # Page Content
        if analysis.get("page_content"):
            pc = analysis["page_content"]
            section("Page Content Analysis", "page")
            reasons = ", ".join(pc.get("risk_reasons", [])) or "None"
            rows([["Page Title",        safe_str(pc.get("page_title"))[:60]],
                  ["Content Risk",      safe_str(pc.get("content_risk"))],
                  ["Password Fields",   str(pc.get("password_inputs", 0))],
                  ["Hidden iFrames",    str(pc.get("hidden_iframes", 0))],
                  ["Obfuscated Code",   str(pc.get("obfuscation_signals", 0))],
                  ["Phishing Keywords", str(pc.get("phishing_keyword_hits", 0))],
                  ["Risk Reasons",      reasons]])

        # Redirects
        if analysis.get("redirects"):
            rd = analysis["redirects"]
            section("Redirect Chain", "redirects")
            chain = rd.get("chain", [])
            rows([["Total Redirects", str(rd.get("redirect_count", len(chain)))],
                  ["Final URL",       safe_str(rd.get("final_url"))],
                  ["Chain",           " -> ".join(chain[:5]) if chain else "Direct (no redirects)"]])

    # ══════════════════════════════════════════════════════════════════════
    #  UPI ANALYSIS SECTIONS
    # ══════════════════════════════════════════════════════════════════════
    if qr_type == "UPI" and upi:
        section("UPI Payment Identity", "upi")
        rows([["UPI ID",        safe_str(upi.get("upi_id"))],
              ["Payee Name",    safe_str(upi.get("payee_name"))],
              ["Platform",      safe_str(upi.get("platform"))],
              ["QR Category",   "Merchant QR" if upi.get("is_merchant_qr") else "Personal QR"],
              ["Amount",        f"Rs. {upi.get('amount', 'Not set')}"],
              ["Currency",      safe_str(upi.get("currency", "INR"))],
              ["Risk Level",    safe_str(upi.get("risk_level"))]])

        if upi.get("bank_name"):
            section("Bank Information", "bank")
            rows([["Bank Name",      safe_str(upi.get("bank_name"))],
                  ["Bank Type",      safe_str(upi.get("bank_type"))],
                  ["Headquarters",   safe_str(upi.get("bank_headquarters"))],
                  ["Customer Care",  safe_str(upi.get("bank_customer_care"))],
                  ["Regulator",      safe_str(upi.get("bank_regulator", "RBI"))],
                  ["Website",        safe_str(upi.get("bank_website"))]])

        if upi.get("phone_number"):
            section("Phone Intelligence")
            rows([["Phone Number",   safe_str(upi.get("phone_formatted"))],
                  ["Carrier",        safe_str(upi.get("phone_carrier"))],
                  ["Mobile Linked",  "Yes" if upi.get("is_mobile_linked") else "No"]])

        # Fraud flags
        fraud_flags = upi.get("fraud_flags", [])
        if fraud_flags:
            section("Fraud Signals Detected", "fraud")
            for i, f in enumerate(fraud_flags, 1):
                sev = f.get("severity", "LOW")
                sev_color = "red" if sev == "HIGH" else "orange" if sev == "MEDIUM" else "gray"
                story.append(Paragraph(
                    f'<font color="{sev_color}"><b>[{sev}]</b></font> {safe_str(f.get("message"))}',
                    normal_s))
            story.append(Spacer(1, 0.3*cm))

        # Transaction risk
        tx = upi.get("transaction_risk", {})
        if tx and tx.get("transaction_risk_score", 0) > 0:
            section("Transaction Risk Analysis")
            rows([["Risk Score",  f"{tx.get('transaction_risk_score', 0)}/100"],
                  ["Risk Level",  safe_str(tx.get("transaction_risk_level"))],
                  ["Amount",      safe_str(tx.get("amount_inr"))],
                  ["Merchant",    "Yes" if tx.get("is_merchant_transaction") else "No"]])

        # Device fingerprint
        df = upi.get("device_fingerprint", {})
        if df and df.get("platform_hint", "Unknown") != "Unknown":
            section("Device Fingerprint")
            rows([["Platform",       safe_str(df.get("platform_hint"))],
                  ["OS Estimate",    safe_str(df.get("os_hint"))],
                  ["Encoding Style", safe_str(df.get("encoding_style"))],
                  ["QR Hash",        safe_str(df.get("qr_structure_hash"))]])

    # ══════════════════════════════════════════════════════════════════════
    #  SANDBOX ANALYSIS
    # ══════════════════════════════════════════════════════════════════════
    if data.get("sandbox_required") and data.get("sandbox_report"):
        sb = data["sandbox_report"]
        section("Dynamic Sandbox Analysis", "sandbox")
        rows([["Malware Score", f"{sb.get('malware_score', 0)}/100"],
              ["JS Executed",   "Yes" if sb.get("js_executed") else "No"],
              ["DNS IPs",       ", ".join(sb.get("dns_ips", []) or ["None"])],
              ["Connections",   ", ".join(sb.get("connections", []) or ["None"])]])

    # ══════════════════════════════════════════════════════════════════════
    #  FORENSIC EVIDENCE
    # ══════════════════════════════════════════════════════════════════════
    if forensic:
        section("Forensic Evidence Report", "forensic")
        if forensic.get("evidence_id"):
            rows([["Evidence ID",    safe_str(forensic.get("evidence_id"))],
                  ["Collected At",   safe_str(forensic.get("timestamp"))],
                  ["Hash (SHA256)",  safe_str(forensic.get("content_hash"))]])
        if forensic.get("domain_intel"):
            di = forensic["domain_intel"]
            story.append(Paragraph("<b>Domain Intelligence:</b>", normal_s))
            rows([["Registrar",   safe_str(di.get("registrar"))],
                  ["Name Servers", safe_str(di.get("name_servers"))],
                  ["Country",     safe_str(di.get("country"))]])
        if forensic.get("ip_intel"):
            ip = forensic["ip_intel"]
            story.append(Paragraph("<b>IP Intelligence:</b>", normal_s))
            rows([["IP",      safe_str(ip.get("ip"))],
                  ["ASN",     safe_str(ip.get("asn"))],
                  ["ISP",     safe_str(ip.get("isp"))],
                  ["Country", safe_str(ip.get("country"))]])

    # ══════════════════════════════════════════════════════════════════════
    #  PREVENTION ACTION
    # ══════════════════════════════════════════════════════════════════════
    prevention = data.get("prevention", {})
    if prevention:
        section("Action Taken", "prevention")
        action = safe_str(prevention.get("action", "NONE"))
        rows([["Action",  action],
              ["Reason",  safe_str(prevention.get("reason"))],
              ["Blocked", "Yes" if data.get("blocked") else "No"]])

    # ══════════════════════════════════════════════════════════════════════
    #  FOOTER
    # ══════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    footer_s = ParagraphStyle("rptFooter", parent=ss["Normal"], fontSize=8,
                              textColor=C.grey, alignment=TA_CENTER)
    story.append(Paragraph(
        "Report Cyber Crime: cybercrime.gov.in | NPCI: 1800-120-1740 | CERT-In: cert-in.org.in",
        footer_s))

    doc.build(story)
    buf.seek(0)
    return buf
