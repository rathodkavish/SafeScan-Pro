import requests
import socket
import ssl
import re
from config import Config
from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
from utils.url_safety import safe_url_or_raise


# ════════════════════════════════════════════════════════════════════════════════
# 1. VirusTotal
# ════════════════════════════════════════════════════════════════════════════════
def check_virustotal(url):
    if not Config.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal key missing"}

    safe_url_or_raise(url)  # SSRF protection
    try:
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if submit.status_code != 200:
            return {"error": "VT submit failed"}

        analysis_id = submit.json()["data"]["id"]
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )

        stats = result.json()["data"]["attributes"]["stats"]

        total = sum(stats.values()) or 1
        risk = (stats.get("malicious", 0) / total) * 100

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "risk_percentage": risk
        }

    except Exception as e:
        return {"error": str(e)}


# ════════════════════════════════════════════════════════════════════════════════
# 2. Google Safe Browsing
# ════════════════════════════════════════════════════════════════════════════════
def check_google_safe_browsing(url):
    if not Config.GOOGLE_SAFE_BROWSING_KEY:
        return {"is_safe": True}

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.GOOGLE_SAFE_BROWSING_KEY}"

    payload = {
        "client": {"clientId": "safescan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(api_url, json=payload, timeout=10)
        matches = r.json().get("matches", [])
        return {"is_safe": len(matches) == 0}
    except:
        return {"is_safe": True}


# ════════════════════════════════════════════════════════════════════════════════
# 3. Domain Age (WHOIS)
# ════════════════════════════════════════════════════════════════════════════════
def check_domain_age(url):
    domain = ""

    safe_url_or_raise(url)  # SSRF protection
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower().replace("www.", "")
        # strip port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        created = None

        # ── Attempt 1: WHOIS lookup ──────────────────────────────────────────
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
        except Exception:
            pass

        # ── Attempt 2: RDAP lookup (works for .in, .io, .dev, etc.) ──────────
        if not created:
            try:
                tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
                rdap_url = f"https://rdap.org/domain/{domain}"
                resp = requests.get(rdap_url, timeout=8, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    rdap_data = resp.json()
                    for event in rdap_data.get("events", []):
                        if event.get("eventAction") == "registration":
                            date_str = event.get("eventDate", "")
                            # Parse ISO 8601 date (e.g. "2025-04-10T12:00:00Z")
                            if date_str:
                                date_str = date_str.replace("Z", "+00:00")
                                created = datetime.fromisoformat(date_str)
                                print(f"✅ RDAP found creation date for {domain}: {created}")
                                break
            except Exception as e:
                print(f"⚠️  RDAP lookup failed for {domain}: {e}")

        if not created:
            print(f"⚠️  No creation date found for {domain} (WHOIS + RDAP both failed)")
            return {
                "domain": domain,
                "age_days": None,
                "is_new": "unknown"
            }

        # ── TIMEZONE FIX ──────────────────────────────────────────────────────
        # python-whois may return timezone-aware datetimes.
        # datetime.utcnow() is naive — subtracting them raises TypeError.
        # Use timezone-aware now() when the creation date carries tzinfo.
        if created.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.utcnow()
        # ─────────────────────────────────────────────────────────────────────

        age_days = (now - created).days

        return {
            "domain": domain,
            "age_days": age_days,
            "is_new": age_days <= 30
        }

    except Exception as e:
        print(f"⚠️  Domain age check failed for {domain}: {e}")
        return {
            "domain": domain,
            "age_days": None,
            "is_new": "unknown"
        }


# ════════════════════════════════════════════════════════════════════════════════
# 4. SSL Certificate Analysis
# ════════════════════════════════════════════════════════════════════════════════
def check_ssl_certificate(url):
    """Connect to host on 443 and read SSL cert details."""
    safe_url_or_raise(url)  # SSRF protection
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        hostname = parsed.netloc.lower().replace("www.", "")
        # Remove port if present
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(8)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        # Parse issuer
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_parts.get("organizationName", issuer_parts.get("commonName", "Unknown"))

        # Parse expiry
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")

        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        issued_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z") if not_before else None

        days_until_expiry = (expiry_dt - datetime.utcnow()).days if expiry_dt else None

        # Parse subject
        subject_parts = dict(x[0] for x in cert.get("subject", []))
        common_name = subject_parts.get("commonName", "N/A")

        # SANs (Subject Alternative Names)
        san_list = []
        for ext_type, ext_val in cert.get("subjectAltName", []):
            if ext_type == "DNS":
                san_list.append(ext_val)

        return {
            "has_ssl": True,
            "issuer": issuer,
            "common_name": common_name,
            "issued": not_before,
            "expiry": not_after,
            "days_until_expiry": days_until_expiry,
            "is_expired": days_until_expiry is not None and days_until_expiry < 0,
            "is_expiring_soon": days_until_expiry is not None and 0 <= days_until_expiry <= 30,
            "subject_alt_names": san_list[:10],  # Limit to 10
            "serial_number": cert.get("serialNumber", "N/A"),
            "version": cert.get("version", "N/A"),
        }

    except ssl.SSLCertVerificationError as e:
        return {"has_ssl": True, "issuer": "INVALID", "error": str(e),
                "is_expired": True, "is_expiring_soon": False, "days_until_expiry": None}
    except Exception:
        return {"has_ssl": False, "issuer": None, "expiry": None,
                "days_until_expiry": None, "is_expired": False, "is_expiring_soon": False}


# ════════════════════════════════════════════════════════════════════════════════
# 5. AbuseIPDB Reputation
# ════════════════════════════════════════════════════════════════════════════════
def check_abuseipdb(url):
    """Resolve domain → IP, then query AbuseIPDB for reputation."""
    safe_url_or_raise(url)  # SSRF protection
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.netloc.lower().replace("www.", "")
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        # Resolve to IP
        ip_address = socket.gethostbyname(hostname)

        api_key = getattr(Config, "ABUSEIPDB_API_KEY", "")
        if not api_key:
            return {
                "ip_address": ip_address,
                "abuse_confidence_score": 0,
                "country_code": "N/A",
                "isp": "N/A",
                "total_reports": 0,
                "is_public": True,
                "error": "No AbuseIPDB API key configured"
            }

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90}
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=10
        )

        if r.status_code != 200:
            return {"ip_address": ip_address, "error": f"AbuseIPDB returned {r.status_code}"}

        data = r.json().get("data", {})
        return {
            "ip_address": data.get("ipAddress", ip_address),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "domain": data.get("domain", hostname),
            "total_reports": data.get("totalReports", 0),
            "is_public": data.get("isPublic", True),
            "usage_type": data.get("usageType", "N/A"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported_at": data.get("lastReportedAt", None),
        }

    except socket.gaierror:
        return {"ip_address": "N/A", "error": "DNS resolution failed", "abuse_confidence_score": 0}
    except Exception as e:
        return {"ip_address": "N/A", "error": str(e), "abuse_confidence_score": 0}


# ════════════════════════════════════════════════════════════════════════════════
# 6. Redirect Chain Analysis
# ════════════════════════════════════════════════════════════════════════════════
def check_redirects(url):
    """Follow redirects and build the chain. Detect cross-domain hops."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        safe_url_or_raise(url)  # SSRF protection

        r = requests.get(url, allow_redirects=True, timeout=12, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        chain = [resp.url for resp in r.history] + [r.url]
        domains = list(set(urlparse(u).netloc.lower().replace("www.", "") for u in chain))

        redirect_count = len(r.history)
        crosses_domains = len(domains) > 1

        # Suspicious if too many redirects or cross-domain
        suspicious = redirect_count >= 3 or (crosses_domains and redirect_count >= 2)

        return {
            "redirect_count": redirect_count,
            "chain": chain,
            "final_url": r.url,
            "crosses_domains": crosses_domains,
            "domains_involved": domains,
            "suspicious": suspicious,
            "status_code": r.status_code,
        }

    except requests.exceptions.TooManyRedirects:
        return {"redirect_count": -1, "chain": [], "final_url": url,
                "crosses_domains": False, "suspicious": True, "error": "Too many redirects"}
    except Exception as e:
        return {"redirect_count": 0, "chain": [url], "final_url": url,
                "crosses_domains": False, "suspicious": False, "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════════
# 7. HTTP Security Headers Analysis
# ════════════════════════════════════════════════════════════════════════════════
def check_http_headers(url):
    """Fetch response headers and grade security posture."""
    SECURITY_HEADERS = {
        "Strict-Transport-Security":   "HSTS — forces HTTPS connections",
        "Content-Security-Policy":     "CSP — prevents XSS and injection attacks",
        "X-Frame-Options":             "Clickjacking protection",
        "X-Content-Type-Options":      "Prevents MIME-type sniffing",
        "X-XSS-Protection":           "Legacy XSS filter",
        "Referrer-Policy":             "Controls referrer information leakage",
        "Permissions-Policy":          "Controls browser feature access",
    }

    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        safe_url_or_raise(url)  # SSRF protection

        r = requests.get(url, timeout=10, allow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        headers_found = {}
        headers_missing = []
        raw_headers = {}

        for hdr, description in SECURITY_HEADERS.items():
            val = r.headers.get(hdr)
            raw_headers[hdr] = val or None
            if val:
                headers_found[hdr] = {"value": val[:120], "description": description}
            else:
                headers_missing.append({"header": hdr, "description": description})

        total = len(SECURITY_HEADERS)
        found = len(headers_found)
        score = round((found / total) * 100)

        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

        # Extra info
        server = r.headers.get("Server", "N/A")
        powered_by = r.headers.get("X-Powered-By", None)
        content_type = r.headers.get("Content-Type", "N/A")

        return {
            "score": score,
            "grade": grade,
            "headers_found": headers_found,
            "headers_missing": headers_missing,
            "total_checked": total,
            "found_count": found,
            "server": server,
            "powered_by": powered_by,
            "content_type": content_type,
        }

    except Exception as e:
        return {"score": 0, "grade": "F", "error": str(e),
                "headers_found": {}, "headers_missing": [], "total_checked": 0, "found_count": 0}


# ════════════════════════════════════════════════════════════════════════════════
# 8. DNS & Infrastructure
# ════════════════════════════════════════════════════════════════════════════════
def check_dns_records(url):
    """Resolve domain IPs, check reverse DNS, detect CDN."""
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.netloc.lower().replace("www.", "")
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        # Get all IPs
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list(set(info[4][0] for info in addr_info))

        # Reverse DNS for primary IP
        reverse_dns = "N/A"
        try:
            reverse_dns = socket.gethostbyaddr(ips[0])[0] if ips else "N/A"
        except:
            pass

        # CDN detection heuristics
        cdn_indicators = ["cloudflare", "akamai", "fastly", "cloudfront", "cdn",
                          "edgecast", "incapsula", "sucuri", "stackpath", "azure"]
        cdn_detected = any(ind in reverse_dns.lower() for ind in cdn_indicators)
        cdn_provider = None
        if cdn_detected:
            for ind in cdn_indicators:
                if ind in reverse_dns.lower():
                    cdn_provider = ind.capitalize()
                    break

        return {
            "hostname": hostname,
            "ip_addresses": ips[:5],
            "ip_count": len(ips),
            "reverse_dns": reverse_dns,
            "cdn_detected": cdn_detected,
            "cdn_provider": cdn_provider,
            "multiple_ips": len(ips) > 1,
        }

    except socket.gaierror:
        return {"hostname": "", "ip_addresses": [], "error": "DNS resolution failed"}
    except Exception as e:
        return {"hostname": "", "ip_addresses": [], "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════════
# 9. Page Content Analysis
# ════════════════════════════════════════════════════════════════════════════════
def analyze_page_content(url):
    """Fetch page and detect suspicious content patterns."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        safe_url_or_raise(url)  # SSRF protection

        r = requests.get(url, timeout=12, allow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        html = r.text[:200000]  # Cap at 200KB
        html_lower = html.lower()

        # Title extraction
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        page_title = title_match.group(1).strip()[:120] if title_match else "N/A"

        # Suspicious forms (password input fields, login forms)
        password_inputs = len(re.findall(r'type\s*=\s*["\']password["\']', html_lower))
        login_forms = len(re.findall(r'<form[^>]*(?:login|signin|auth)[^>]*>', html_lower))

        # External scripts
        script_tags = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
        external_scripts = [s for s in script_tags if s.startswith(("http://", "https://", "//"))]

        # Iframes
        iframes = re.findall(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
        hidden_iframes = len(re.findall(
            r'<iframe[^>]*(?:style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0))',
            html_lower
        ))

        # Obfuscation signals
        obfuscation_signals = 0
        if "eval(" in html_lower: obfuscation_signals += 1
        if "document.write(" in html_lower: obfuscation_signals += 1
        if "unescape(" in html_lower: obfuscation_signals += 1
        if "atob(" in html_lower: obfuscation_signals += 1
        if "\\x" in html and html.count("\\x") > 10: obfuscation_signals += 1
        if "fromcharcode" in html_lower: obfuscation_signals += 1

        # Data URI usage (potential payload hiding)
        data_uris = len(re.findall(r'data:[^;]+;base64,', html_lower))

        # Meta refresh redirect
        meta_refresh = bool(re.search(r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\']', html_lower))

        # Crypto mining detection
        crypto_miners = any(m in html_lower for m in ["coinhive", "cryptoloot", "coin-hive", "minero", "jsecoin"])

        # Phishing keyword density
        phishing_keywords = ["verify your account", "confirm your identity", "update your payment",
                             "suspended", "unusual activity", "click here immediately",
                             "act now", "limited time", "your account will be"]
        keyword_hits = sum(1 for kw in phishing_keywords if kw in html_lower)

        # Risk assessment
        content_risk = "LOW"
        risk_reasons = []
        if password_inputs > 0:
            risk_reasons.append(f"{password_inputs} password field(s)")
        if hidden_iframes > 0:
            risk_reasons.append(f"{hidden_iframes} hidden iframe(s)")
        if obfuscation_signals >= 2:
            risk_reasons.append(f"{obfuscation_signals} obfuscation signals")
        if meta_refresh:
            risk_reasons.append("Meta refresh redirect")
        if crypto_miners:
            risk_reasons.append("Crypto miner detected")
        if keyword_hits >= 2:
            risk_reasons.append(f"{keyword_hits} phishing keywords")
        if data_uris > 3:
            risk_reasons.append(f"{data_uris} data URIs (potential payload hiding)")

        if len(risk_reasons) >= 3:
            content_risk = "HIGH"
        elif len(risk_reasons) >= 1:
            content_risk = "MEDIUM"

        return {
            "page_title": page_title,
            "password_inputs": password_inputs,
            "login_forms": login_forms,
            "external_scripts_count": len(external_scripts),
            "external_scripts": external_scripts[:5],
            "iframes_count": len(iframes),
            "hidden_iframes": hidden_iframes,
            "obfuscation_signals": obfuscation_signals,
            "data_uris": data_uris,
            "meta_refresh": meta_refresh,
            "crypto_miner_detected": crypto_miners,
            "phishing_keyword_hits": keyword_hits,
            "content_risk": content_risk,
            "risk_reasons": risk_reasons,
            "page_size_kb": round(len(html) / 1024, 1),
        }

    except Exception as e:
        return {"page_title": "N/A", "content_risk": "UNKNOWN", "error": str(e),
                "risk_reasons": []}
