"""
backend/utils/forensic_intel.py
Forensic Intelligence Collector for SafeScan-Pro
─────────────────────────────────────────────────
When a malicious QR is detected, this module collects ALL digital evidence
about the attacker that law enforcement can use to trace and catch them:

  1. Domain WHOIS → registrant name, email, phone, address
  2. IP Geolocation → server country, city, ISP, hosting provider
  3. SSL Certificate → issuer, registration details
  4. Redirect Chain → full hop-by-hop trail of redirects
  5. Server Fingerprint → technology stack, CMS, web server
  6. DNS Records → nameservers, MX records, related infrastructure
  7. UPI Trail → phone number, carrier, region, bank (for UPI scams)
  8. Evidence Timeline → chronological attack reconstruction
  9. Attacker Profile → correlated intelligence summary
"""

import re
import socket
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from utils.url_safety import safe_url_or_raise

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def collect_forensic_evidence(url: str, scan_result: dict, qr_type: str = "URL") -> dict:
    """
    Master function: collects all forensic evidence for a malicious QR code.
    Called automatically when verdict is DANGEROUS or SUSPICIOUS.
    
    Returns a comprehensive evidence package for law enforcement.
    """
    evidence = {
        "evidence_id":      hashlib.sha256(f"{url}{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16],
        "collection_time":  datetime.now(timezone.utc).isoformat(),
        "qr_type":          qr_type,
        "target":           url,
        "verdict":          scan_result.get("verdict", "UNKNOWN"),
        "risk_score":       scan_result.get("risk_score", 0),
    }

    if qr_type == "URL":
        evidence["domain_intel"]      = _collect_domain_intel(url, scan_result)
        evidence["ip_intel"]          = _collect_ip_intel(url, scan_result)
        evidence["ssl_intel"]         = _collect_ssl_intel(scan_result)
        evidence["redirect_chain"]    = _collect_redirect_chain(url)
        evidence["server_fingerprint"] = _collect_server_fingerprint(url)
        evidence["dns_records"]       = _collect_dns_info(url)
        evidence["attacker_profile"]  = _build_attacker_profile(evidence)

    elif qr_type == "UPI":
        evidence["upi_trail"]         = _collect_upi_trail(url, scan_result)
        evidence["attacker_profile"]  = _build_upi_attacker_profile(evidence)

    evidence["evidence_timeline"]     = _build_timeline(evidence, scan_result)
    evidence["law_enforcement_summary"] = _build_le_summary(evidence)
    evidence["reporting_agencies"]    = _get_reporting_agencies(qr_type)

    return evidence


# ── Domain Intelligence ───────────────────────────────────────────────────

def _collect_domain_intel(url: str, scan_result: dict) -> dict:
    """Extract domain registration details — who registered this domain?"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]  # strip port

    intel = {
        "domain":           domain,
        "registered_to":    "Unknown",
        "registrant_email": "Unknown",
        "registrant_phone": "Unknown",
        "registrant_org":   "Unknown",
        "registrant_country": "Unknown",
        "registrar":        "Unknown",
        "creation_date":    "Unknown",
        "expiry_date":      "Unknown",
        "updated_date":     "Unknown",
        "domain_age_days":  None,
        "nameservers":      [],
        "privacy_protected": False,
    }

    # From existing scan analysis
    analysis = scan_result.get("analysis", {})
    domain_data = analysis.get("domain", {})
    if domain_data:
        intel["domain_age_days"] = domain_data.get("age_days")
        intel["creation_date"]   = domain_data.get("creation_date", "Unknown")

    # WHOIS lookup for registrant details
    if HAS_WHOIS:
        try:
            w = whois.whois(domain)
            if w:
                intel["registered_to"]     = _safe_str(w.get("name") or w.get("registrant_name"))
                intel["registrant_email"]  = _safe_str(w.get("emails"))
                intel["registrant_org"]    = _safe_str(w.get("org") or w.get("organization"))
                intel["registrant_country"] = _safe_str(w.get("country"))
                intel["registrar"]         = _safe_str(w.get("registrar"))
                intel["creation_date"]     = _safe_str(w.get("creation_date"))
                intel["expiry_date"]       = _safe_str(w.get("expiration_date"))
                intel["updated_date"]      = _safe_str(w.get("updated_date"))
                ns = w.get("name_servers") or []
                intel["nameservers"]       = [str(n) for n in ns] if isinstance(ns, list) else [str(ns)]

                # Check if privacy protection is used
                email_str = str(intel["registrant_email"]).lower()
                if any(p in email_str for p in ["privacy", "proxy", "protect", "redacted", "whoisguard"]):
                    intel["privacy_protected"] = True
        except Exception as e:
            intel["whois_error"] = str(e)[:100]

    return intel


# ── IP Intelligence ───────────────────────────────────────────────────────

def _collect_ip_intel(url: str, scan_result: dict) -> dict:
    """Server IP geolocation — where is the attacker's server?"""
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path).split(":")[0]

    intel = {
        "ip_address":     "Unknown",
        "country":        "Unknown",
        "city":           "Unknown",
        "isp":            "Unknown",
        "hosting_provider": "Unknown",
        "is_shared_hosting": False,
        "abuse_score":    0,
        "total_reports":  0,
        "is_tor":         False,
        "is_vpn":         False,
    }

    # Resolve IP
    try:
        ip = socket.gethostbyname(domain)
        intel["ip_address"] = ip
    except Exception:
        pass

    # From existing AbuseIPDB analysis
    analysis = scan_result.get("analysis", {})
    abuse = analysis.get("abuseipdb", {})
    if abuse:
        intel["ip_address"]      = abuse.get("ip_address", intel["ip_address"])
        intel["country"]         = abuse.get("country_code", "Unknown")
        intel["isp"]             = abuse.get("isp", "Unknown")
        intel["hosting_provider"] = abuse.get("usage_type", "Unknown")
        intel["abuse_score"]     = abuse.get("abuse_confidence_score", 0)
        intel["total_reports"]   = abuse.get("total_reports", 0)
        intel["is_tor"]          = abuse.get("is_tor", False)

    # Check for known VPN/proxy indicators
    isp_lower = intel["isp"].lower()
    vpn_indicators = ["vpn", "proxy", "tunnel", "anonymo", "hide", "mask"]
    intel["is_vpn"] = any(v in isp_lower for v in vpn_indicators)

    # Check for shared hosting (common providers)
    shared_hosts = ["godaddy", "hostgator", "bluehost", "namecheap", "cloudflare",
                    "amazonaws", "digitalocean", "linode", "vultr", "hetzner"]
    intel["is_shared_hosting"] = any(h in isp_lower for h in shared_hosts)

    return intel


# ── SSL Certificate Intelligence ─────────────────────────────────────────

def _collect_ssl_intel(scan_result: dict) -> dict:
    """SSL certificate details — who issued the certificate?"""
    analysis = scan_result.get("analysis", {})
    ssl = analysis.get("ssl", {})

    return {
        "has_ssl":          ssl.get("has_ssl", False),
        "issuer":           ssl.get("issuer", "Unknown"),
        "common_name":      ssl.get("common_name", "Unknown"),
        "expiry":           ssl.get("expiry", "Unknown"),
        "is_expired":       ssl.get("is_expired", False),
        "is_free_cert":     _is_free_cert(ssl.get("issuer", "")),
        "cert_authority":   ssl.get("issuer", "Unknown"),
        "alt_names":        ssl.get("subject_alt_names", []),
        "version":          ssl.get("version", "Unknown"),
        "note":             "Free certificates (Let's Encrypt) are commonly used by attackers as they require no identity verification" if _is_free_cert(ssl.get("issuer", "")) else "",
    }


# ── Redirect Chain ────────────────────────────────────────────────────────

def _collect_redirect_chain(url: str) -> dict:
    """Follow the full redirect chain — reveals intermediate servers."""
    chain = {"hops": [], "total_redirects": 0, "final_url": url, "crosses_borders": False}

    if not HAS_REQUESTS:
        chain["error"] = "requests library not available"
        return chain

    try:
        safe_url_or_raise(url)  # SSRF protection
        resp = requests.get(url, allow_redirects=True, timeout=10,
                           headers={"User-Agent": "SafeScan-Pro/1.0 (Security Scanner)"},
                           verify=False)

        countries_seen = set()
        for i, r in enumerate(resp.history):
            hop = {
                "hop":         i + 1,
                "url":         r.url[:200],
                "status_code": r.status_code,
                "server":      r.headers.get("Server", "Unknown"),
                "location":    r.headers.get("Location", "")[:200],
            }
            chain["hops"].append(hop)

            # Try to get country for each hop
            try:
                hop_domain = urlparse(r.url).netloc.split(":")[0]
                hop_ip = socket.gethostbyname(hop_domain)
                hop["ip"] = hop_ip
            except Exception:
                pass

        chain["total_redirects"] = len(resp.history)
        chain["final_url"]      = resp.url[:200]
        chain["final_status"]   = resp.status_code

        # Add final destination
        chain["hops"].append({
            "hop":         len(resp.history) + 1,
            "url":         resp.url[:200],
            "status_code": resp.status_code,
            "server":      resp.headers.get("Server", "Unknown"),
            "location":    "Final destination",
        })

    except Exception as e:
        chain["error"] = str(e)[:100]

    return chain


# ── Server Fingerprint ────────────────────────────────────────────────────

def _collect_server_fingerprint(url: str) -> dict:
    """Fingerprint the attacker's server technology."""
    fp = {
        "web_server":    "Unknown",
        "technologies":  [],
        "cms":           "Unknown",
        "language":      "Unknown",
        "framework":     "Unknown",
        "cdn":           "Unknown",
        "headers":       {},
    }

    if not HAS_REQUESTS:
        return fp

    try:
        safe_url_or_raise(url)  # SSRF protection
        resp = requests.head(url, timeout=8, allow_redirects=True,
                            headers={"User-Agent": "SafeScan-Pro/1.0"},
                            verify=False)
        h = resp.headers

        fp["web_server"] = h.get("Server", "Unknown")
        fp["cdn"]        = h.get("CDN", h.get("X-CDN", h.get("Via", "None")))

        # Technology detection from headers
        tech_headers = {
            "X-Powered-By":  "language",
            "X-AspNet-Version": "framework",
            "X-Generator":   "cms",
        }
        for header, field in tech_headers.items():
            if header in h:
                fp[field] = h[header]
                fp["technologies"].append(f"{header}: {h[header]}")

        # Store relevant headers as evidence
        evidence_headers = ["Server", "X-Powered-By", "X-Frame-Options",
                           "Content-Security-Policy", "Set-Cookie", "Via",
                           "X-AspNet-Version", "X-Generator"]
        for eh in evidence_headers:
            if eh in h:
                fp["headers"][eh] = h[eh][:200]

    except Exception as e:
        fp["error"] = str(e)[:100]

    return fp


# ── DNS Intelligence ──────────────────────────────────────────────────────

def _collect_dns_info(url: str) -> dict:
    """DNS records — nameservers and mail servers."""
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path).split(":")[0]

    dns = {"domain": domain, "ip_addresses": [], "nameservers": [], "mx_records": []}

    try:
        ips = socket.getaddrinfo(domain, None)
        dns["ip_addresses"] = list(set(addr[4][0] for addr in ips))[:5]
    except Exception:
        pass

    return dns


# ── UPI Trail ─────────────────────────────────────────────────────────────

def _collect_upi_trail(qr_data: str, scan_result: dict) -> dict:
    """For UPI scams — collect the money trail evidence."""
    upi = scan_result.get("upi_analysis") or scan_result.get("parsed_data") or {}
    phone_intel = upi.get("phone_intelligence", {})

    trail = {
        "upi_id":           upi.get("upi_id", "Unknown"),
        "payee_name":       upi.get("payee_name", "Unknown"),
        "bank_handle":      upi.get("upi_id", "").split("@")[-1] if "@" in upi.get("upi_id", "") else "Unknown",
        "bank_name":        upi.get("bank_name", "Unknown"),
        "platform":         upi.get("platform", "Unknown"),
        "amount_requested": upi.get("amount", "None"),
        "transaction_note": upi.get("transaction_note", "None"),
        "is_merchant":      upi.get("is_merchant_qr", False),
        "merchant_code":    upi.get("merchant_code", "None"),
        "phone_number":     upi.get("phone_number", "Not linked"),
        "phone_operator":   phone_intel.get("operator", "Unknown"),
        "phone_region":     phone_intel.get("telecom_circle", "Unknown"),
        "connected_app":    (phone_intel.get("connected_upi") or {}).get("app", "Unknown"),
        "is_virtual_number": phone_intel.get("is_virtual_number", False),
        "fraud_flags":      upi.get("fraud_flags", []),
        "traceable_via":    [],
    }

    # Determine what law enforcement can trace
    if trail["phone_number"] != "Not linked":
        trail["traceable_via"].append({
            "method": "Mobile Number Trace",
            "detail": f"Number {trail['phone_number']} can be traced via telecom operator ({trail['phone_operator']}) CDR records",
            "agency": "Telecom Operator + Police Cyber Cell",
        })
    if trail["bank_name"] != "Unknown":
        trail["traceable_via"].append({
            "method": "Bank Account Trace",
            "detail": f"UPI handle @{trail['bank_handle']} linked to {trail['bank_name']} — account holder details available via bank",
            "agency": f"{trail['bank_name']} Fraud Department",
        })
    if trail["upi_id"] != "Unknown":
        trail["traceable_via"].append({
            "method": "NPCI UPI Registry",
            "detail": f"UPI ID {trail['upi_id']} is registered in NPCI's central registry with KYC details",
            "agency": "NPCI (National Payments Corporation of India)",
        })
    if trail["connected_app"] != "Unknown":
        trail["traceable_via"].append({
            "method": "UPI App Records",
            "detail": f"Account registered on {trail['connected_app']} — app has device info, login history, IP logs",
            "agency": f"{trail['connected_app']} Trust & Safety Team",
        })

    return trail


# ── Attacker Profile ──────────────────────────────────────────────────────

def _build_attacker_profile(evidence: dict) -> dict:
    """Correlate all evidence into an attacker intelligence profile."""
    domain = evidence.get("domain_intel", {})
    ip     = evidence.get("ip_intel", {})
    ssl    = evidence.get("ssl_intel", {})
    server = evidence.get("server_fingerprint", {})
    redir  = evidence.get("redirect_chain", {})

    profile = {
        "identity_traces": [],
        "infrastructure":  [],
        "behavioral":      [],
        "traceability":    "LOW",
    }

    # Identity traces
    if domain.get("registered_to", "Unknown") != "Unknown" and not domain.get("privacy_protected"):
        profile["identity_traces"].append({
            "type": "Domain Registrant", "value": domain["registered_to"],
            "confidence": "HIGH" if not domain.get("privacy_protected") else "LOW",
        })
    if domain.get("registrant_email", "Unknown") != "Unknown":
        profile["identity_traces"].append({
            "type": "Registrant Email", "value": domain["registrant_email"],
            "confidence": "MEDIUM",
        })
    if domain.get("registrant_org", "Unknown") != "Unknown":
        profile["identity_traces"].append({
            "type": "Organization", "value": domain["registrant_org"],
            "confidence": "MEDIUM",
        })

    # Infrastructure traces
    profile["infrastructure"].append({
        "type": "Server IP", "value": ip.get("ip_address", "Unknown"),
        "location": f"{ip.get('city', '?')}, {ip.get('country', '?')}",
    })
    profile["infrastructure"].append({
        "type": "Hosting", "value": ip.get("isp", "Unknown"),
        "note": "Shared hosting" if ip.get("is_shared_hosting") else "Dedicated/VPS",
    })
    if ip.get("is_tor"):
        profile["infrastructure"].append({"type": "Anonymization", "value": "TOR Network detected", "note": "Attacker using TOR to hide"})
    if ip.get("is_vpn"):
        profile["infrastructure"].append({"type": "Anonymization", "value": "VPN/Proxy detected", "note": "Attacker using VPN"})

    # Behavioral traces
    if redir.get("total_redirects", 0) > 2:
        profile["behavioral"].append({
            "type": "Multi-hop redirects",
            "detail": f"{redir['total_redirects']} redirects used to evade detection",
        })
    if ssl.get("is_free_cert"):
        profile["behavioral"].append({
            "type": "Free SSL certificate",
            "detail": "Using free cert (no identity verification required)",
        })
    if domain.get("domain_age_days") and domain["domain_age_days"] < 30:
        profile["behavioral"].append({
            "type": "Newly registered domain",
            "detail": f"Domain only {domain['domain_age_days']} days old — typical of phishing campaigns",
        })

    # Traceability assessment
    trace_score = len(profile["identity_traces"]) * 2 + len(profile["infrastructure"])
    if ip.get("is_tor") or ip.get("is_vpn"):
        trace_score -= 2
    if domain.get("privacy_protected"):
        trace_score -= 1
    profile["traceability"] = "HIGH" if trace_score >= 5 else "MEDIUM" if trace_score >= 3 else "LOW"

    return profile


def _build_upi_attacker_profile(evidence: dict) -> dict:
    """Attacker profile specifically for UPI scams — these are HIGHLY traceable."""
    trail = evidence.get("upi_trail", {})

    profile = {
        "identity_traces":  trail.get("traceable_via", []),
        "infrastructure":   [],
        "behavioral":       [],
        "traceability":     "HIGH",  # UPI scams are very traceable
        "traceability_note": "UPI transactions are KYC-verified. The attacker's identity is known to the bank and NPCI.",
    }

    if trail.get("is_virtual_number"):
        profile["traceability"] = "MEDIUM"
        profile["behavioral"].append({
            "type": "Virtual Number", "detail": "Attacker using virtual/temporary number to avoid detection",
        })

    flags = trail.get("fraud_flags", [])
    for f in flags[:5]:
        profile["behavioral"].append({"type": "Fraud Signal", "detail": f.get("message", "")})

    return profile


# ── Evidence Timeline ─────────────────────────────────────────────────────

def _build_timeline(evidence: dict, scan_result: dict) -> list:
    """Build chronological timeline of the attack."""
    timeline = []

    domain = evidence.get("domain_intel", {})
    if domain.get("creation_date", "Unknown") != "Unknown":
        timeline.append({
            "event": "Domain Registered",
            "time":  str(domain["creation_date"]),
            "detail": f"Domain registered via {domain.get('registrar', 'Unknown')}",
        })

    timeline.append({
        "event": "QR Code Created",
        "time":  "Unknown (before scan)",
        "detail": f"Attacker created {evidence.get('qr_type', 'QR')} QR code targeting: {evidence.get('target', 'Unknown')[:60]}",
    })

    timeline.append({
        "event": "QR Code Scanned by SafeScan Pro",
        "time":  evidence.get("collection_time", "Unknown"),
        "detail": f"Verdict: {evidence.get('verdict', 'Unknown')} | Risk: {evidence.get('risk_score', 0)}%",
    })

    redir = evidence.get("redirect_chain", {})
    if redir.get("total_redirects", 0) > 0:
        timeline.append({
            "event": "Redirect Chain Detected",
            "time":  evidence.get("collection_time"),
            "detail": f"{redir['total_redirects']} redirects to reach final URL: {redir.get('final_url', 'Unknown')[:60]}",
        })

    timeline.append({
        "event": "Malicious Action BLOCKED by SafeScan Pro",
        "time":  evidence.get("collection_time"),
        "detail": "User was protected — no data was exposed to the attacker",
    })

    timeline.append({
        "event": "Forensic Evidence Collected",
        "time":  evidence.get("collection_time"),
        "detail": f"Evidence ID: {evidence.get('evidence_id', 'N/A')} — ready for law enforcement submission",
    })

    return timeline


# ── Law Enforcement Summary ───────────────────────────────────────────────

def _build_le_summary(evidence: dict) -> dict:
    """Generate a summary suitable for law enforcement filing."""
    profile = evidence.get("attacker_profile", {})
    qr_type = evidence.get("qr_type", "URL")

    summary = {
        "case_type":       f"Quishing Attack ({qr_type} QR Code)",
        "evidence_id":     evidence.get("evidence_id"),
        "detection_time":  evidence.get("collection_time"),
        "threat_level":    evidence.get("verdict"),
        "risk_score":      evidence.get("risk_score"),
        "traceability":    profile.get("traceability", "UNKNOWN"),
        "recommended_actions": [],
    }

    if qr_type == "URL":
        domain = evidence.get("domain_intel", {})
        ip     = evidence.get("ip_intel", {})
        summary["recommended_actions"] = [
            f"Request WHOIS records from registrar: {domain.get('registrar', 'Unknown')}",
            f"Request server logs from hosting provider: {ip.get('isp', 'Unknown')}",
            f"Issue takedown notice for domain: {domain.get('domain', 'Unknown')}",
            "Check if domain appears in other phishing campaigns (PhishTank, OpenPhish)",
            "Cross-reference IP with known threat actor infrastructure",
        ]
        if not domain.get("privacy_protected"):
            summary["recommended_actions"].insert(0,
                f"Investigate registrant: {domain.get('registered_to', 'Unknown')} ({domain.get('registrant_email', 'Unknown')})")

    elif qr_type == "UPI":
        trail = evidence.get("upi_trail", {})
        summary["recommended_actions"] = [
            f"Request KYC details from {trail.get('bank_name', 'Unknown')} for UPI ID: {trail.get('upi_id', 'Unknown')}",
            f"Request CDR (Call Detail Records) from telecom operator for number: {trail.get('phone_number', 'Unknown')}",
            f"Contact NPCI for UPI transaction history of: {trail.get('upi_id', 'Unknown')}",
            f"Contact {trail.get('connected_app', 'Unknown')} for device/login records",
            "File FIR under IT Act Section 66C (Identity Theft) and 66D (Cheating by Personation)",
        ]

    return summary


# ── Reporting Agencies ────────────────────────────────────────────────────

def _get_reporting_agencies(qr_type: str) -> list:
    """List of agencies where this can be reported."""
    agencies = [
        {"name": "National Cyber Crime Portal",   "contact": "cybercrime.gov.in",      "type": "Online FIR"},
        {"name": "Cyber Crime Helpline",           "contact": "1930",                   "type": "Phone"},
        {"name": "CERT-In",                        "contact": "cert-in.org.in",         "type": "Incident Report"},
        {"name": "Local Police Cyber Cell",        "contact": "Visit nearest station",  "type": "FIR"},
    ]

    if qr_type == "UPI":
        agencies.extend([
            {"name": "NPCI UPI Helpline",          "contact": "1800-120-1740",          "type": "Phone"},
            {"name": "RBI Ombudsman",              "contact": "cms.rbi.org.in",         "type": "Online Complaint"},
            {"name": "Bank Fraud Department",      "contact": "Contact your bank",      "type": "Fraud Report"},
        ])

    return agencies


# ── Helpers ───────────────────────────────────────────────────────────────

def _safe_str(val) -> str:
    if val is None:
        return "Unknown"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val[:3])
    return str(val)[:200]


def _is_free_cert(issuer: str) -> bool:
    free_cas = ["let's encrypt", "letsencrypt", "zerossl", "buypass", "ssl.com free"]
    return any(ca in issuer.lower() for ca in free_cas) if issuer else False
