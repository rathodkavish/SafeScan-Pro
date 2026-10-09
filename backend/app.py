import os
import time
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from pymongo import MongoClient

from config import Config
from utils.feature_extractor import get_feature_vector
from utils.api_integrations import (
    check_virustotal,
    check_google_safe_browsing,
    check_domain_age,
    check_ssl_certificate,
    check_abuseipdb,
    check_redirects,
    check_http_headers,
    check_dns_records,
    analyze_page_content,
)
from utils.qr_decoder import decode_qr_image
from models.url_classifier import url_classifier
from utils.qr_type_detector import detect_qr_type
from utils.non_url_qr_analyzer import analyze_non_url_qr
from utils.sandbox_client import analyze_in_sandbox
from utils.threat_db import (
    init_threat_db, lookup_threat, save_threat,
    get_threat_stats, get_prevention_action,
)
from utils.forensic_intel import collect_forensic_evidence
from utils.url_safety import validate_url

load_dotenv()
print("VirusTotal Key Loaded:", bool(Config.VIRUSTOTAL_API_KEY))

# ── MongoDB & Storage Fallback ────────────────────────────────────────────────
from utils.local_storage_db import get_local_db

MONGO_URI = os.getenv("MONGO_URI")
history_collection = None
mongo_connected = False

if MONGO_URI:
    try:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        mongo_client.admin.command("ping")
        mongo_db = mongo_client["safescan"]
        history_collection = mongo_db["scan_history"]
        init_threat_db(mongo_db)
        mongo_connected = True
        print("✅ MongoDB Atlas connected")
    except Exception as e:
        print("⚠️  MongoDB Atlas not reachable:", e)

if not mongo_connected:
    print("📁 Storage Fallback: Local database activated (persistent scan_history & threat_cache active)")
    local_db = get_local_db()
    history_collection = local_db["scan_history"]
    init_threat_db(local_db)

# ── In-Memory Cache (10 min TTL) ──────────────────────────────────────────────
_cache: dict = {}
CACHE_TTL = 600
MAX_CACHE  = 200

def _cache_key(url: str) -> str:
    return hashlib.md5(url.strip().lower().encode()).hexdigest()

def _cache_get(url: str):
    entry = _cache.get(_cache_key(url))
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        # Invalidate stale cache entries missing score_breakdown
        if "score_breakdown" not in entry.get("data", {}):
            del _cache[_cache_key(url)]
            return None
        print(f"⚡ Cache HIT: {url[:60]}")
        return entry["data"]
    return None

def _cache_set(url: str, data: dict):
    if len(_cache) >= MAX_CACHE:
        oldest = min(_cache, key=lambda k: _cache[k]["ts"])
        del _cache[oldest]
    _cache[_cache_key(url)] = {"ts": time.time(), "data": data}

# ── Trusted domain fast-path ──────────────────────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com","www.google.com","google.co.in",
    "youtube.com","www.youtube.com",
    "facebook.com","www.facebook.com",
    "instagram.com","www.instagram.com",
    "twitter.com","x.com","www.twitter.com",
    "linkedin.com","www.linkedin.com",
    "github.com","www.github.com",
    "microsoft.com","www.microsoft.com",
    "apple.com","www.apple.com",
    "amazon.com","www.amazon.com","amazon.in","www.amazon.in",
    "flipkart.com","www.flipkart.com",
    "paytm.com","www.paytm.com",
    "phonepe.com","www.phonepe.com",
    "gpay.app","pay.google.com",
    "hdfcbank.com","www.hdfcbank.com",
    "icicibank.com","www.icicibank.com",
    "sbi.co.in","www.sbi.co.in","onlinesbi.sbi",
    "axisbank.com","www.axisbank.com",
    "kotak.com","www.kotak.com",
    "npci.org.in","www.npci.org.in",
    "wikipedia.org","www.wikipedia.org",
    "whatsapp.com","www.whatsapp.com",
    "zoom.us","www.zoom.us",
}

def _is_trusted(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        host = urlparse(url if url.startswith("http") else "https://" + url).hostname or ""
        return host.lower() in TRUSTED_DOMAINS
    except Exception:
        return False

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB file upload limit (prevents DoS)
CORS(app)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
url_classifier.load()
print("✅ ML model loaded")


@app.after_request
def add_security_headers(response):
    response.headers['ngrok-skip-browser-warning'] = 'true'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ── Serve Expo Web UI from root ───────────────────────────────────────────────
from flask import send_from_directory

WEBUI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui")

@app.route("/_expo/<path:path>")
def serve_expo_assets(path):
    return send_from_directory(os.path.join(WEBUI_DIR, "_expo"), path)

@app.route("/assets/<path:path>")
def serve_webui_assets(path):
    return send_from_directory(os.path.join(WEBUI_DIR, "assets"), path)

@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(WEBUI_DIR, "favicon.ico")

@app.route("/web")
@app.route("/web/")
@app.route("/web/<path:path>")
def serve_web_ui(path=""):
    """Serve the Expo web app at /web. All sub-routes resolve to HTML pages."""
    if path and os.path.isfile(os.path.join(WEBUI_DIR, path)):
        return send_from_directory(WEBUI_DIR, path)
    if path and os.path.isfile(os.path.join(WEBUI_DIR, path + ".html")):
        return send_from_directory(WEBUI_DIR, path + ".html")
    return send_from_directory(WEBUI_DIR, "index.html")

# ── Normalizers ───────────────────────────────────────────────────────────────
def allowed_file(f):
    if not f:
        return False
    if "." not in f:
        return True  # Allow browser default blob uploads without extension
    return f.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "webp", "bmp", "gif"}

def normalize_domain_info(d):
    if not isinstance(d, dict):
        return {"domain": "", "is_new": False, "age_days": None}
    age = d.get("age_days")
    return {
        "domain":   d.get("domain", ""),
        "is_new":   bool(d.get("is_new", False)) if age is not None else False,
        "age_days": int(age) if isinstance(age, (int, float)) else None,
    }

def normalize_ml_result(ml):
    if not isinstance(ml, dict):
        return {"is_phishing": False, "confidence": 0}
    return {
        "is_phishing": bool(ml.get("is_phishing", False)),
        "confidence":  float(ml.get("confidence", 0)),
    }

def normalize_gsb_result(gsb):
    if not isinstance(gsb, dict):
        return {"is_safe": True}
    return {"is_safe": bool(gsb.get("is_safe", True))}

def normalize_vt_result(vt):
    if not isinstance(vt, dict):
        return {"malicious": 0, "suspicious": 0, "risk_percentage": 0, "error": "no data"}
    # Preserve the error key so calculate_score knows VT failed
    result = {
        "malicious":       vt.get("malicious", 0),
        "suspicious":      vt.get("suspicious", 0),
        "risk_percentage": vt.get("risk_percentage", 0),
    }
    if "error" in vt:
        result["error"] = vt["error"]
    return result

def normalize_sandbox_report(r):
    if not isinstance(r, dict):
        return {"js_executed": None, "redirects": [], "downloads": [],
                "dns_ips": [], "connections": [], "malware_score": 0}
    return {
        "js_executed":   r.get("js_executed"),
        "redirects":     r.get("redirects", []),
        "downloads":     r.get("downloads", []),
        "dns_ips":       r.get("dns_ips", []),
        "connections":   r.get("connections") or r.get("network_connections", []),
        "malware_score": r.get("malware_score", 0),
    }

def should_use_sandbox(domain_info):
    age = domain_info.get("age_days")
    return age is None or age <= 30

def ensure_url_scheme(url):
    return url if url.startswith(("http://", "https://")) else "https://" + url

def calculate_score(ml, vt, gsb, domain, page_content=None, sandbox_report=None,
                    ssl_info=None, redirect_info=None, http_headers_info=None):
    """
    Returns dict: {"score": float, "breakdown": [...]}
    Each breakdown item shows how a signal contributed to the final score.
    """
    score = 0.0
    breakdown = []
    gsb_flagged = not gsb.get("is_safe", True)
    vt_flagged = ("error" not in vt and vt.get("risk_percentage", 0) > 10)
    ml_phishing = ml.get("is_phishing", False)
    ml_conf = ml.get("confidence", 0)

    # ML Model
    if ml_phishing:
        pts = round(ml_conf * 0.35, 1)
        score += pts
        breakdown.append({"signal": "ML Phishing Model", "points": pts, "max": 35,
            "status": "THREAT", "detail": "Phishing detected (%.0f%% confidence)" % ml_conf})
    else:
        if not gsb_flagged and not vt_flagged:
            if ml_conf > 70:
                score -= 10
                breakdown.append({"signal": "ML Phishing Model", "points": -10, "max": 35,
                    "status": "SAFE", "detail": "Safe (%.0f%% confidence) - safe bonus" % ml_conf})
            elif ml_conf > 50:
                score -= 5
                breakdown.append({"signal": "ML Phishing Model", "points": -5, "max": 35,
                    "status": "SAFE", "detail": "Safe (%.0f%% confidence)" % ml_conf})
            else:
                breakdown.append({"signal": "ML Phishing Model", "points": 0, "max": 35,
                    "status": "NEUTRAL", "detail": "Low confidence (%.0f%%) - inconclusive" % ml_conf})
        else:
            breakdown.append({"signal": "ML Phishing Model", "points": 0, "max": 35,
                "status": "OVERRIDE", "detail": "ML safe but overridden by threat database"})

    # VirusTotal
    if "error" not in vt and "risk_percentage" in vt:
        vt_risk = vt["risk_percentage"]
        pts = round(vt_risk * 0.25, 1)
        score += pts
        mal = vt.get("malicious", 0)
        st = "THREAT" if vt_flagged else "SAFE"
        breakdown.append({"signal": "VirusTotal", "points": pts, "max": 25,
            "status": st, "detail": "%d engine(s) flagged (%.0f%% risk)" % (mal, vt_risk)})
    else:
        breakdown.append({"signal": "VirusTotal", "points": 0, "max": 25,
            "status": "SKIP", "detail": vt.get("error", "API not available")})

    # Google Safe Browsing
    if gsb_flagged:
        score += 40
        breakdown.append({"signal": "Google Safe Browsing", "points": 40, "max": 40,
            "status": "THREAT", "detail": "Flagged in Google phishing/malware database"})
    else:
        breakdown.append({"signal": "Google Safe Browsing", "points": 0, "max": 40,
            "status": "SAFE", "detail": "Not in Google threat database"})

    # Domain age
    age = domain.get("age_days")
    is_new = domain.get("is_new")
    if is_new == "unknown" or (age is None and is_new != False):
        # WHOIS + RDAP both failed — treat as cautious (half penalty)
        score += 6
        breakdown.append({"signal": "Domain Age", "points": 6, "max": 12,
            "status": "WARN", "detail": "Could not verify domain age (WHOIS/RDAP failed)"})
    elif is_new is True or (isinstance(age, (int, float)) and age <= 30):
        score += 12
        breakdown.append({"signal": "Domain Age", "points": 12, "max": 12,
            "status": "THREAT", "detail": "Domain only %s day(s) old" % str(age or "?")})
    else:
        age_str = "%s days" % str(age) if age else "Established"
        breakdown.append({"signal": "Domain Age", "points": 0, "max": 12,
            "status": "SAFE", "detail": "Domain age: %s" % age_str})

    # Page content
    if page_content:
        cr = page_content.get("content_risk", "LOW")
        reasons = page_content.get("risk_reasons", [])
        reason_str = ", ".join(reasons[:3]) if reasons else "none"
        if cr == "HIGH":
            score += 15
            breakdown.append({"signal": "Page Content", "points": 15, "max": 15,
                "status": "THREAT", "detail": "High risk: %s" % reason_str})
        elif cr == "MEDIUM":
            score += 7
            breakdown.append({"signal": "Page Content", "points": 7, "max": 15,
                "status": "WARN", "detail": "Medium risk: %s" % reason_str})
        else:
            breakdown.append({"signal": "Page Content", "points": 0, "max": 15,
                "status": "SAFE", "detail": "No suspicious patterns"})

    # Sandbox
    if sandbox_report and isinstance(sandbox_report, dict):
        malware = sandbox_report.get("malware_score", 0) or 0
        pts = round(min(malware, 100) * 0.20, 1)
        score += pts
        st = "THREAT" if malware > 30 else "SAFE"
        breakdown.append({"signal": "Sandbox Analysis", "points": pts, "max": 20,
            "status": st, "detail": "Malware score: %d/100" % malware})

    # ── Multi-Signal Correlation (expanded — 6 signals) ────────────────
    domain_new = (domain.get("is_new") is True
                  or (isinstance(domain.get("age_days"), (int, float))
                      and domain["age_days"] <= 30))
    page_high = (page_content is not None
                 and page_content.get("content_risk") == "HIGH")
    sandbox_flagged = (sandbox_report is not None
                       and isinstance(sandbox_report, dict)
                       and (sandbox_report.get("malware_score", 0) or 0) > 30)

    all_signals = {
        "ML": ml_phishing, "GSB": gsb_flagged, "VT": vt_flagged,
        "Domain": domain_new, "Page": page_high, "Sandbox": sandbox_flagged,
    }
    threat_signal_count = sum(1 for v in all_signals.values() if v)
    triggered_names = [n for n, f in all_signals.items() if f]

    if threat_signal_count >= 3:
        score += 15
        breakdown.append({"signal": "Multi-Signal Correlation", "points": 15, "max": 15,
            "status": "THREAT",
            "detail": "%d/6 signals agree: %s" % (threat_signal_count, ", ".join(triggered_names))})
    elif threat_signal_count >= 2:
        score += 10
        breakdown.append({"signal": "Multi-Signal Correlation", "points": 10, "max": 15,
            "status": "THREAT",
            "detail": "%d/6 signals agree: %s" % (threat_signal_count, ", ".join(triggered_names))})

    # ── Forensic Pattern Match ────────────────────────────────────────────
    # Detects known attack PATTERNS by combining individually weak signals.
    # Individual signal scores remain untouched — this is a separate analysis.
    pattern_points = 0
    pattern_details = []

    # Pattern 1: Classic Phishing Setup (ML + new domain + suspicious page)
    has_pw_fields = (page_content is not None
                     and (page_content.get("password_inputs", 0) or 0) > 0)
    if ml_phishing and domain_new and (page_high or has_pw_fields):
        pattern_points += 20
        pattern_details.append("Classic phishing setup (ML + new domain + suspicious page)")

    # Pattern 2: Evasion Tactics (redirects + free/no SSL + obfuscation)
    has_many_redirects = (redirect_info is not None
                          and isinstance(redirect_info, dict)
                          and (redirect_info.get("redirect_count", 0)
                               or len(redirect_info.get("chain", []))) > 2)
    has_free_ssl = (ssl_info is not None and isinstance(ssl_info, dict)
                    and (not ssl_info.get("has_ssl", True)
                         or any(ca in (ssl_info.get("issuer") or "").lower()
                                for ca in ["let's encrypt", "letsencrypt",
                                           "zerossl", "buypass"])))
    has_obfuscation = (page_content is not None
                       and (page_content.get("obfuscation_signals", 0) or 0) > 0)
    evasion_indicators = [
        ("redirects", has_many_redirects),
        ("free/no SSL", has_free_ssl),
        ("obfuscated JS", has_obfuscation),
    ]
    evasion_count = sum(1 for _, f in evasion_indicators if f)
    if evasion_count >= 2:
        pattern_points += 15
        matched = ", ".join(n for n, f in evasion_indicators if f)
        pattern_details.append("Evasion tactics (%d indicators: %s)" % (evasion_count, matched))

    # Pattern 3: Infrastructure Red Flags (new domain + weak headers)
    poor_headers = (http_headers_info is not None
                    and isinstance(http_headers_info, dict)
                    and (http_headers_info.get("score", 100) or 100) < 30)
    if domain_new and poor_headers:
        pattern_points += 12
        pattern_details.append("Infrastructure red flags (new domain + weak security headers)")

    # Pattern 4: Unverifiable Target (VT unavailable + ML flags + new domain)
    vt_skipped = "error" in vt
    if vt_skipped and ml_phishing and domain_new:
        pattern_points += 10
        pattern_details.append("Unverifiable target (VT unavailable + ML phishing + new domain)")

    # Cap at 20 max
    pattern_points = min(pattern_points, 20)

    if pattern_points > 0:
        score += pattern_points
        breakdown.append({"signal": "Forensic Pattern Match", "points": pattern_points, "max": 20,
            "status": "THREAT", "detail": "; ".join(pattern_details)})
    else:
        breakdown.append({"signal": "Forensic Pattern Match", "points": 0, "max": 20,
            "status": "SAFE", "detail": "No known attack patterns detected"})

    # ── Normalize breakdown so max values sum to 100 ──────────────────────
    breakdown, final = _normalize_breakdown(breakdown, score)

    # Security Guard: Confirmed threats should never be diluted below verdict thresholds
    if ml_phishing and gsb_flagged and final < 70.0:
        final = 75.0
    elif gsb_flagged and final < 40.0:
        final = 45.0

    return {"score": final, "breakdown": breakdown}


def _normalize_breakdown(breakdown: list, raw_score: float) -> tuple:
    """
    Scales breakdown 'max' AND 'points' by the same factor so max values
    sum to exactly 100. Each signal's points will never exceed its max.
    The final score = sum of scaled points (clamped 0-100).
    """
    total_max = sum(b["max"] for b in breakdown)
    if total_max <= 0:
        return breakdown, 0
    if total_max == 100:
        final = min(max(round(raw_score, 2), 0), 100)
        return breakdown, final

    scale = 100.0 / total_max
    for b in breakdown:
        b["points"] = round(b["points"] * scale, 1)
        b["max"]    = round(b["max"] * scale)
        # Safety cap: points never exceed their max
        if b["points"] > b["max"]:
            b["points"] = float(b["max"])

    # Fix rounding on max: ensure they sum to exactly 100
    diff = 100 - sum(b["max"] for b in breakdown)
    if diff != 0 and breakdown:
        largest = max(breakdown, key=lambda b: b["max"])
        largest["max"] += diff

    final = min(max(round(sum(b["points"] for b in breakdown), 2), 0), 100)
    return breakdown, final

def calculate_non_url_score(analysis: dict, qr_type: str = "UPI") -> dict:
    """
    Generates risk_score and score_breakdown for non-URL QR types (UPI, WIFI, SMS, etc.)
    based on fraud signals detected by analyze_non_url_qr().
    Individual fraud signals are mapped to transparent breakdown entries.
    """
    score = 0.0
    breakdown = []
    parsed = analysis.get("parsed_data") or analysis.get("upi_analysis") or {}
    fraud_flags = parsed.get("fraud_flags", [])
    risk_level = parsed.get("risk_level", "LOW")
    tx_risk = parsed.get("transaction_risk", {})

    # ── Signal 1: Fraud Signal Analysis (max 40) ─────────────────────────
    high_flags = [f for f in fraud_flags if f.get("severity") == "HIGH"]
    med_flags  = [f for f in fraud_flags if f.get("severity") == "MEDIUM"]
    flag_pts = min(len(high_flags) * 15 + len(med_flags) * 8, 40)
    if flag_pts > 0:
        flag_msgs = [f.get("message", "")[:60] for f in (high_flags + med_flags)[:3]]
        breakdown.append({"signal": "Fraud Signal Analysis", "points": flag_pts, "max": 40,
            "status": "THREAT" if high_flags else "WARN",
            "detail": "%d fraud signal(s): %s" % (len(high_flags) + len(med_flags),
                      "; ".join(flag_msgs))})
    else:
        breakdown.append({"signal": "Fraud Signal Analysis", "points": 0, "max": 40,
            "status": "SAFE", "detail": "No fraud signals detected"})
    score += flag_pts

    # ── Signal 2: Transaction Risk (max 25) ──────────────────────────────
    tx_score = tx_risk.get("transaction_risk_score", 0) if tx_risk else 0
    tx_pts = round(min(tx_score, 100) * 0.25, 1)
    tx_level = tx_risk.get("transaction_risk_level", "LOW") if tx_risk else "LOW"
    if tx_pts > 0:
        tx_signals = tx_risk.get("risk_signals", []) if tx_risk else []
        tx_detail = "; ".join(s.get("detail", "")[:50] for s in tx_signals[:2]) or "Elevated risk"
        breakdown.append({"signal": "Transaction Risk", "points": tx_pts, "max": 25,
            "status": "THREAT" if tx_level == "HIGH" else "WARN",
            "detail": tx_detail})
    else:
        breakdown.append({"signal": "Transaction Risk", "points": 0, "max": 25,
            "status": "SAFE", "detail": "Normal transaction parameters"})
    score += tx_pts

    # ── Signal 3: Identity Verification (max 20) ─────────────────────────
    id_pts = 0
    id_details = []
    payee = parsed.get("payee_name", "")
    is_merchant = parsed.get("is_merchant_qr", False)
    # Check impersonation patterns in payee name
    impersonation_words = ["cashback", "refund", "prize", "lottery", "win",
                           "reward", "government", "rbi", "helpdesk", "support"]
    if any(w in payee.lower() for w in impersonation_words):
        id_pts += 15
        id_details.append("Impersonation in payee name: '%s'" % payee[:40])
    # Personal QR pretending to be official
    if not is_merchant and payee and any(w in payee.lower() for w in
            ["official", "bank", "paytm", "phonepe", "gpay", "sbi", "hdfc", "icici"]):
        id_pts += 10
        id_details.append("Personal QR using official brand name")
    id_pts = min(id_pts, 20)
    if id_pts > 0:
        breakdown.append({"signal": "Identity Verification", "points": id_pts, "max": 20,
            "status": "THREAT", "detail": "; ".join(id_details)})
    else:
        breakdown.append({"signal": "Identity Verification", "points": 0, "max": 20,
            "status": "SAFE", "detail": "No impersonation detected"})
    score += id_pts

    # ── Signal 4: QR Category Risk (max 15) ──────────────────────────────
    cat_pts = 0
    if qr_type == "UPI":
        amt = 0
        try:
            amt = float(parsed.get("amount", 0) or 0)
        except (ValueError, TypeError):
            pass
        if not is_merchant and amt > 10000:
            cat_pts = 15
            breakdown.append({"signal": "QR Category Risk", "points": 15, "max": 15,
                "status": "THREAT",
                "detail": "Personal QR requesting large payment: Rs.%.0f" % amt})
        elif not is_merchant and amt > 5000:
            cat_pts = 10
            breakdown.append({"signal": "QR Category Risk", "points": 10, "max": 15,
                "status": "WARN",
                "detail": "Personal QR with pre-set amount: Rs.%.0f" % amt})
        elif not is_merchant and amt > 0:
            cat_pts = 5
            breakdown.append({"signal": "QR Category Risk", "points": 5, "max": 15,
                "status": "WARN",
                "detail": "Personal QR with pre-set amount: Rs.%.0f" % amt})
        else:
            breakdown.append({"signal": "QR Category Risk", "points": 0, "max": 15,
                "status": "SAFE", "detail": "Standard %s QR" % ("merchant" if is_merchant else "personal")})
    elif qr_type == "WIFI":
        sec = (parsed.get("security") or "NONE").upper()
        if sec in ["NOPASS", "NONE", ""]:
            cat_pts = 15
            breakdown.append({"signal": "QR Category Risk", "points": 15, "max": 15,
                "status": "THREAT", "detail": "Open WiFi — no password protection"})
        else:
            breakdown.append({"signal": "QR Category Risk", "points": 0, "max": 15,
                "status": "SAFE", "detail": "WiFi with %s security" % sec})
    elif qr_type == "APP":
        if "play.google.com" not in (parsed.get("url") or "").lower():
            cat_pts = 15
            breakdown.append({"signal": "QR Category Risk", "points": 15, "max": 15,
                "status": "THREAT", "detail": "Non-PlayStore app installation"})
        else:
            breakdown.append({"signal": "QR Category Risk", "points": 0, "max": 15,
                "status": "SAFE", "detail": "Official app store link"})
    else:
        breakdown.append({"signal": "QR Category Risk", "points": 0, "max": 15,
            "status": "SAFE", "detail": "Standard %s QR" % qr_type})
    score += cat_pts

    # ── Normalize breakdown so max values sum to 100 ──────────────────────
    breakdown, final = _normalize_breakdown(breakdown, score)
    return {"score": final, "breakdown": breakdown}

# ── Parallel Analysis ─────────────────────────────────────────────────────────
def run_parallel_analysis(url: str) -> dict:
    t0 = time.time()
    trusted = _is_trusted(url)

    # ML is local — instant, no I/O
    features = get_feature_vector(url)
    ml = normalize_ml_result(url_classifier.predict(features))

    # All external tasks — skip heavy ones for trusted domains
    tasks: dict = {
        "vt":     lambda: normalize_vt_result(check_virustotal(url)),
        "gsb":    lambda: normalize_gsb_result(check_google_safe_browsing(url)),
        "domain": lambda: normalize_domain_info(check_domain_age(url)),
        "abuse":  lambda: check_abuseipdb(url),
        "dns":    lambda: check_dns_records(url),
    }
    if not trusted:
        tasks["ssl"]          = lambda: check_ssl_certificate(url)
        tasks["redirects"]    = lambda: check_redirects(url)
        tasks["http_headers"] = lambda: check_http_headers(url)
        tasks["page_content"] = lambda: analyze_page_content(url)

    results: dict = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        future_map = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map, timeout=22):
            name = future_map[future]
            try:
                results[name] = future.result(timeout=3)
            except Exception as e:
                print(f"⚠️  {name} failed: {e}")
                results[name] = None

    # Safe defaults
    results.setdefault("vt",           normalize_vt_result(None))
    results.setdefault("gsb",          normalize_gsb_result(None))
    results.setdefault("domain",       normalize_domain_info(None))
    results.setdefault("abuse",        None)
    results.setdefault("dns",          None)
    results.setdefault("ssl",          None)
    results.setdefault("redirects",    None)
    results.setdefault("http_headers", None)
    results.setdefault("page_content", None)
    results["ml"] = ml

    print(f"⏱  analysis done in {time.time()-t0:.2f}s (trusted={trusted})")
    return results

def build_result(url, r, sandbox_required, qr_type="URL", sandbox_report=None):
    score_result = calculate_score(
        r["ml"], r["vt"], r["gsb"], r["domain"],
        page_content=r.get("page_content"),
        sandbox_report=sandbox_report,
        ssl_info=r.get("ssl"),
        redirect_info=r.get("redirects"),
        http_headers_info=r.get("http_headers"),
    )
    risk = score_result["score"]
    breakdown = score_result["breakdown"]
    verdict = "SAFE" if risk < 24 else "SUSPICIOUS" if risk < 42 else "DANGEROUS"
    return {
        "url":              url,
        "risk_score":       round(risk, 2),
        "score_breakdown":  breakdown,
        "verdict":          verdict,
        "sandbox_required": sandbox_required,
        "sandbox_report":   sandbox_report,
        "qr_type":          qr_type,
        "analysis": {
            "ml":                   r["ml"],
            "virustotal":           r["vt"],
            "google_safe_browsing": r["gsb"],
            "domain":               r["domain"],
            "ssl":                  r.get("ssl"),
            "redirects":            r.get("redirects"),
            "abuseipdb":            r.get("abuse"),
            "dns":                  r.get("dns"),
            "http_headers":         r.get("http_headers"),
            "page_content":         r.get("page_content"),
        },
        "time": datetime.utcnow().isoformat(),
    }

_recent_scans = []

def save_history(data):
    # Keep last 50 in-memory scans
    try:
        _recent_scans.append(dict(data))
        if len(_recent_scans) > 50:
            _recent_scans.pop(0)
    except Exception:
        pass

    if history_collection is not None:
        try:
            history_collection.insert_one(data)
        except Exception as e:
            print("❌ Mongo insert failed:", e)

def _run_sandbox(url):
    try:
        return normalize_sandbox_report(analyze_in_sandbox(ensure_url_scheme(url)))
    except Exception as e:
        print(f"⚠️  sandbox failed: {e}")
        return None

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return jsonify({"status": "running", "cache_entries": len(_cache)})

@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.json or {}
    url  = data.get("url")
    if not url:
        return jsonify({"error": "URL required"}), 400

    # ── Step 0: SSRF & URL Safety Validation ─────────────────────────────
    val = validate_url(url)
    if not val.get("safe", True):
        reason = val.get("reason", "Blocked internal/unsafe URL")
        print(f"🛡 SSRF Guard BLOCKED: {url[:60]} → {reason}")
        return jsonify({
            "url": url,
            "verdict": "DANGEROUS",
            "risk_score": 100.0,
            "blocked": True,
            "qr_type": "URL",
            "prevention": {
                "action": "BLOCK_URL",
                "icon": "🚫",
                "message": f"Blocked security risk: {reason}"
            },
            "score_breakdown": [
                {
                    "signal": "SSRF Guard",
                    "points": 100.0,
                    "max": 100,
                    "status": "THREAT",
                    "detail": reason
                }
            ],
            "time": datetime.utcnow().isoformat()
        }), 200

    # ── Step 1: Check threat database FIRST ──────────────────────────────
    threat_hit = lookup_threat(url)
    if threat_hit:
        print(f"🛡  Threat DB HIT: {url[:60]} → {threat_hit['verdict']}")
        cached_result = threat_hit.get("result_snapshot", {})
        cached_result.update({
            "url":              url,
            "from_threat_db":   True,
            "blocked":          True,
            "verdict":          threat_hit["verdict"],
            "risk_score":       threat_hit.get("risk_score", 0),
            "qr_type":          threat_hit.get("qr_type", "URL"),
            "scan_count":       threat_hit.get("scan_count", 0),
            "blocked_count":    threat_hit.get("blocked_count", 0),
            "first_seen":       threat_hit.get("first_seen"),
            "community_flagged": threat_hit.get("is_community_flagged", False),
            "reported_by_users": threat_hit.get("reported_by_users", 0),
            "prevention":       get_prevention_action("URL", threat_hit["verdict"], {}),
            "time":             datetime.utcnow().isoformat(),
        })
        # Generate score_breakdown for old DB entries that lack it
        if "score_breakdown" not in cached_result:
            analysis = cached_result.get("analysis", {})
            ml = analysis.get("ml", {})
            vt = analysis.get("virustotal", {})
            gsb = analysis.get("google_safe_browsing", {})
            dom = analysis.get("domain", {})
            score_result = calculate_score(ml, vt, gsb, dom)
            cached_result["score_breakdown"] = score_result["breakdown"]
        return jsonify(cached_result)

    # ── Step 2: Check in-memory cache ────────────────────────────────────
    cached = _cache_get(url)
    if cached:
        return jsonify(cached)

    # ── Step 3: Full analysis ────────────────────────────────────────────
    r                = run_parallel_analysis(url)
    sandbox_required = should_use_sandbox(r["domain"]) and not _is_trusted(url)
    sandbox_report   = _run_sandbox(url) if sandbox_required else None
    result           = build_result(url, r, sandbox_required, "URL", sandbox_report)

    # ── Step 4: Add prevention info ──────────────────────────────────────
    result["prevention"]     = get_prevention_action("URL", result["verdict"], result)
    result["blocked"]        = result["verdict"] == "DANGEROUS"
    result["from_threat_db"] = False

    # ── Step 5: Collect forensic evidence for threats ─────────────────────
    if result["verdict"] in ("DANGEROUS", "SUSPICIOUS"):
        try:
            result["forensic_evidence"] = collect_forensic_evidence(url, result, "URL")
        except Exception as e:
            print(f"⚠️  Forensic collection failed: {e}")

    # ── Step 6: Save to threat DB + cache ────────────────────────────────
    _cache_set(url, result)
    save_threat(url, result["verdict"], result, "URL",
                result["prevention"].get("action", "NONE"))
    save_history({"type": "url", "data": result})
    return jsonify(result)

@app.route("/api/scan-qr", methods=["POST"])
def scan_qr():
    if "qr_image" not in request.files:
        return jsonify({"error": "No QR image uploaded. Please select an image file."}), 400
    file = request.files["qr_image"]
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file format. Please upload a PNG, JPG, or JPEG image."}), 400

    filename = secure_filename(file.filename) if file.filename else ""
    if not filename or "." not in filename:
        filename = f"qr_{int(time.time())}.png"
    filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
    file.save(filepath)

    qr_data = decode_qr_image(filepath)
    if not qr_data:
        return jsonify({"error": "No QR detected in the selected image. Please make sure the QR code is clear and not blurry."}), 400

    # ── Threat DB check ──────────────────────────────────────────────────
    qr_type = detect_qr_type(qr_data)
    threat_hit = lookup_threat(qr_data)
    if threat_hit:
        print(f"🛡  Threat DB HIT (QR image): {qr_data[:60]} → {threat_hit['verdict']}")
        cached_result = threat_hit.get("result_snapshot", {})
        cached_result.update({
            "qr_data":          qr_data,
            "from_threat_db":   True,
            "blocked":          True,
            "verdict":          threat_hit["verdict"],
            "risk_score":       threat_hit.get("risk_score", 0),
            "qr_type":          threat_hit.get("qr_type", qr_type),
            "scan_count":       threat_hit.get("scan_count", 0),
            "blocked_count":    threat_hit.get("blocked_count", 0),
            "first_seen":       threat_hit.get("first_seen"),
            "community_flagged": threat_hit.get("is_community_flagged", False),
            "reported_by_users": threat_hit.get("reported_by_users", 0),
            "prevention":       get_prevention_action(qr_type, threat_hit["verdict"], {}),
            "time":             datetime.utcnow().isoformat(),
        })
        if "score_breakdown" not in cached_result:
            _qt = cached_result.get("qr_type", qr_type)
            if _qt != "URL" and (_qt in ("UPI","WIFI","SMS","APP","EMAIL","PHONE","TEXT","CONTACT","GEO")):
                _non_url = {"parsed_data": cached_result.get("parsed_data", cached_result.get("upi_analysis", {}))}
                _sr = calculate_non_url_score(_non_url, _qt)
            else:
                _a = cached_result.get("analysis", {})
                _sr = calculate_score(_a.get("ml",{}), _a.get("virustotal",{}), _a.get("google_safe_browsing",{}), _a.get("domain",{}))
            cached_result["score_breakdown"] = _sr["breakdown"]
            if cached_result.get("risk_score", 0) == 0 and _sr["score"] > 0:
                cached_result["risk_score"] = _sr["score"]
        return jsonify(cached_result)

    if qr_type == "URL":
        val = validate_url(qr_data)
        if not val.get("safe", True):
            reason = val.get("reason", "Blocked internal/unsafe URL")
            print(f"🛡 SSRF Guard BLOCKED QR URL: {qr_data[:60]} → {reason}")
            res = {
                "qr_data": qr_data, "url": qr_data, "qr_type": "URL",
                "verdict": "DANGEROUS", "risk_score": 100.0, "blocked": True,
                "prevention": {"action": "BLOCK_URL", "icon": "🚫", "message": f"Blocked security risk: {reason}"},
                "score_breakdown": [{"signal": "SSRF Guard", "points": 100.0, "max": 100, "status": "THREAT", "detail": reason}],
                "time": datetime.utcnow().isoformat()
            }
            save_history({"type": "qr", "data": res})
            return jsonify(res), 200

        cached = _cache_get(qr_data)
        if cached:
            return jsonify(cached)
        r                = run_parallel_analysis(qr_data)
        sandbox_required = should_use_sandbox(r["domain"]) and not _is_trusted(qr_data)
        sandbox_report   = _run_sandbox(qr_data) if sandbox_required else None
        result           = build_result(qr_data, r, sandbox_required, "URL", sandbox_report)
        result["qr_data"]       = qr_data
        result["prevention"]    = get_prevention_action("URL", result["verdict"], result)
        result["blocked"]       = result["verdict"] == "DANGEROUS"
        result["from_threat_db"] = False
        _cache_set(qr_data, result)
        save_threat(qr_data, result["verdict"], result, "URL",
                    result["prevention"].get("action", "NONE"))
    else:
        analysis = analyze_non_url_qr(qr_type, qr_data)
        non_url_score = calculate_non_url_score(analysis, qr_type)
        result   = {
            "qr_data": qr_data, "qr_type": qr_type,
            "verdict": analysis["reputation"], "confidence": analysis["confidence"],
            "risk_score": non_url_score["score"],
            "score_breakdown": non_url_score["breakdown"],
            "sandbox_required": False, "reason": analysis["reason"],
            "sandbox_report": None,
            "parsed_data":  analysis.get("parsed_data", {}),
            "upi_analysis": analysis.get("upi_analysis", None),
            "is_upi":       analysis.get("is_upi", False),
            "prevention":   get_prevention_action(qr_type, analysis["reputation"], analysis),
            "prevention_actions": analysis.get("prevention_actions", []),
            "blocked":       analysis["reputation"] == "DANGEROUS",
            "from_threat_db": False,
            "time":         datetime.utcnow().isoformat(),
        }
        # Forensic evidence for threats
        if result["verdict"] in ("DANGEROUS", "SUSPICIOUS"):
            try:
                result["forensic_evidence"] = collect_forensic_evidence(qr_data, result, qr_type)
            except Exception as e:
                print(f"⚠️  Forensic collection failed: {e}")
        save_threat(qr_data, result["verdict"], result, qr_type,
                    result["prevention"].get("action", "NONE"))

    save_history({"type": "qr", "data": result})
    return jsonify(result)

@app.route("/api/scan-qr-data", methods=["POST"])
def scan_qr_data():
    data    = request.json or {}
    qr_data = data.get("qr_data", "")
    qr_type = data.get("qr_type", "") or detect_qr_type(qr_data)

    if not qr_data:
        return jsonify({"error": "qr_data required"}), 400

    # ── Threat DB check ──────────────────────────────────────────────────
    threat_hit = lookup_threat(qr_data)
    if threat_hit:
        print(f"🛡  Threat DB HIT (data): {qr_data[:60]} → {threat_hit['verdict']}")
        cached_result = threat_hit.get("result_snapshot", {})
        cached_result.update({
            "qr_data":          qr_data,
            "from_threat_db":   True,
            "blocked":          True,
            "verdict":          threat_hit["verdict"],
            "risk_score":       threat_hit.get("risk_score", 0),
            "qr_type":          threat_hit.get("qr_type", qr_type),
            "scan_count":       threat_hit.get("scan_count", 0),
            "blocked_count":    threat_hit.get("blocked_count", 0),
            "first_seen":       threat_hit.get("first_seen"),
            "community_flagged": threat_hit.get("is_community_flagged", False),
            "reported_by_users": threat_hit.get("reported_by_users", 0),
            "prevention":       get_prevention_action(qr_type, threat_hit["verdict"], {}),
            "time":             datetime.utcnow().isoformat(),
        })
        if "score_breakdown" not in cached_result:
            _qt = cached_result.get("qr_type", qr_type)
            if _qt != "URL" and (_qt in ("UPI","WIFI","SMS","APP","EMAIL","PHONE","TEXT","CONTACT","GEO")):
                _non_url = {"parsed_data": cached_result.get("parsed_data", cached_result.get("upi_analysis", {}))}
                _sr = calculate_non_url_score(_non_url, _qt)
            else:
                analysis = cached_result.get("analysis", {})
                ml = analysis.get("ml", {})
                vt = analysis.get("virustotal", {})
                gsb = analysis.get("google_safe_browsing", {})
                dom = analysis.get("domain", {})
                _sr = calculate_score(ml, vt, gsb, dom)
            cached_result["score_breakdown"] = _sr["breakdown"]
            if cached_result.get("risk_score", 0) == 0 and _sr["score"] > 0:
                cached_result["risk_score"] = _sr["score"]
        return jsonify(cached_result)

    if qr_type == "URL":
        val = validate_url(qr_data)
        if not val.get("safe", True):
            reason = val.get("reason", "Blocked internal/unsafe URL")
            print(f"🛡 SSRF Guard BLOCKED QR Data URL: {qr_data[:60]} → {reason}")
            res = {
                "qr_data": qr_data, "url": qr_data, "qr_type": "URL",
                "verdict": "DANGEROUS", "risk_score": 100.0, "blocked": True,
                "prevention": {"action": "BLOCK_URL", "icon": "🚫", "message": f"Blocked security risk: {reason}"},
                "score_breakdown": [{"signal": "SSRF Guard", "points": 100.0, "max": 100, "status": "THREAT", "detail": reason}],
                "time": datetime.utcnow().isoformat()
            }
            save_history({"type": "qr_data", "data": res})
            return jsonify(res), 200

        cached = _cache_get(qr_data)
        if cached:
            return jsonify(cached)
        r                = run_parallel_analysis(qr_data)
        sandbox_required = should_use_sandbox(r["domain"]) and not _is_trusted(qr_data)
        sandbox_report   = _run_sandbox(qr_data) if sandbox_required else None
        result           = build_result(qr_data, r, sandbox_required, "URL", sandbox_report)
        result["qr_data"]       = qr_data
        result["prevention"]    = get_prevention_action("URL", result["verdict"], result)
        result["blocked"]       = result["verdict"] == "DANGEROUS"
        result["from_threat_db"] = False
        # Forensic evidence for URL threats
        if result["verdict"] in ("DANGEROUS", "SUSPICIOUS"):
            try:
                result["forensic_evidence"] = collect_forensic_evidence(qr_data, result, "URL")
            except Exception as e:
                print(f"⚠️  Forensic collection failed: {e}")
        _cache_set(qr_data, result)
        save_threat(qr_data, result["verdict"], result, "URL",
                    result["prevention"].get("action", "NONE"))
    else:
        analysis = analyze_non_url_qr(qr_type, qr_data)
        non_url_score = calculate_non_url_score(analysis, qr_type)
        result   = {
            "qr_data": qr_data, "qr_type": qr_type,
            "verdict": analysis["reputation"], "confidence": analysis["confidence"],
            "risk_score": non_url_score["score"],
            "score_breakdown": non_url_score["breakdown"],
            "sandbox_required": analysis.get("sandbox_required", False),
            "reason": analysis["reason"], "sandbox_report": None,
            "parsed_data":  analysis.get("parsed_data", {}),
            "upi_analysis": analysis.get("upi_analysis", None),
            "is_upi":       analysis.get("is_upi", False),
            "prevention":   get_prevention_action(qr_type, analysis["reputation"], analysis),
            "prevention_actions": analysis.get("prevention_actions", []),
            "blocked":       analysis["reputation"] == "DANGEROUS",
            "from_threat_db": False,
            "time":         datetime.utcnow().isoformat(),
        }
        # Forensic evidence for threats
        if result["verdict"] in ("DANGEROUS", "SUSPICIOUS"):
            try:
                result["forensic_evidence"] = collect_forensic_evidence(qr_data, result, qr_type)
            except Exception as e:
                print(f"⚠️  Forensic collection failed: {e}")
        save_threat(qr_data, result["verdict"], result, qr_type,
                    result["prevention"].get("action", "NONE"))

    save_history({"type": "qr_data", "data": result})
    return jsonify(result)

@app.route("/api/history", methods=["GET"])
def get_history():
    if history_collection is not None:
        try:
            records = list(
                history_collection.find({}, {"_id": 0}).sort("data.time", -1).limit(50)
            )
            return jsonify({"count": len(records), "history": records})
        except Exception as e:
            print("❌ Mongo find failed:", e)

    # Fallback to in-memory session history
    return jsonify({"count": len(_recent_scans), "history": list(reversed(_recent_scans))})

# ── Threat Database Endpoints ─────────────────────────────────────────────
@app.route("/api/threat-stats", methods=["GET"])
def threat_stats():
    """Returns threat database statistics for the dashboard."""
    stats = get_threat_stats()
    return jsonify(stats)

@app.route("/api/threat-lookup", methods=["POST"])
def threat_lookup():
    """Check if a QR code is in the threat database."""
    data    = request.json or {}
    qr_data = data.get("qr_data", "")
    if not qr_data:
        return jsonify({"error": "qr_data required"}), 400
    hit = lookup_threat(qr_data)
    if hit:
        return jsonify({"found": True, **hit})
    return jsonify({"found": False, "message": "QR not in threat database"})

@app.route("/api/download-report", methods=["POST"])
def download_report():
    try:
        from utils.pdf_report import generate_report
        from flask import Response
    except ImportError as e:
        return jsonify({"error": f"PDF dependency missing: {e}"}), 500

    data = request.json or {}
    buf  = generate_report(data)
    return Response(
        buf.getvalue(), mimetype="application/pdf",
        headers={"Content-Disposition":
                 f"attachment; filename=SafeScan_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"})

if __name__ == "__main__":
    print("🚀 SafeScan Backend started")
    app.run(host="0.0.0.0", port=5000, debug=False)
