"""
backend/utils/threat_db.py
Persistent QR Threat Intelligence Database
───────────────────────────────────────────
- Stores every scan result (SAFE / SUSPICIOUS / DANGEROUS) in MongoDB
- Hashes QR content (SHA-256) for instant repeat lookups
- DANGEROUS/SUSPICIOUS QRs are flagged so future scans skip full analysis
- Community reporting: users can flag QRs, increasing threat confidence
- Provides threat statistics for the dashboard
"""

import hashlib
import re
from datetime import datetime, timezone

# ── Module-level reference (set by init_threat_db) ────────────────────────────
_threat_col = None   # MongoDB collection: threat_cache
_stats_col  = None   # MongoDB collection: threat_stats


def init_threat_db(mongo_db):
    """
    Call once at startup with the pymongo Database object.
    Creates indexes for fast lookups.
    """
    global _threat_col, _stats_col

    _threat_col = mongo_db["threat_cache"]
    _stats_col  = mongo_db["threat_stats"]

    # Ensure indexes
    _threat_col.create_index("qr_hash", unique=True)
    _threat_col.create_index("verdict")
    _threat_col.create_index("last_seen")
    _threat_col.create_index("qr_type")

    # Ensure a single stats document exists
    if _stats_col.count_documents({}) == 0:
        _stats_col.insert_one({
            "_id":                "global",
            "total_scans":        0,
            "total_threats":      0,
            "total_blocked":      0,
            "total_safe":         0,
            "total_reports":      0,
            "threats_by_type":    {},
            "last_updated":       datetime.now(timezone.utc).isoformat(),
        })

    print("✅ Threat DB initialized (indexes created)")


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_qr_content(qr_data: str) -> str:
    """
    Normalize and hash QR content for reliable matching.
    - Strip whitespace, lowercase for comparison
    - SHA-256 for collision resistance
    """
    normalized = qr_data.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ── Lookup ────────────────────────────────────────────────────────────────────

def lookup_threat(qr_data: str) -> dict | None:
    """
    Check if this QR content has been seen before.
    Returns the cached result if DANGEROUS or SUSPICIOUS, None otherwise.
    Also increments scan_count and updates last_seen.
    """
    if _threat_col is None:
        return None

    qr_hash = hash_qr_content(qr_data)

    try:
        doc = _threat_col.find_one({"qr_hash": qr_hash})
        if not doc:
            return None

        # Only return cached result for threats (not SAFE)
        verdict = doc.get("verdict", "SAFE")
        if verdict not in ("DANGEROUS", "SUSPICIOUS"):
            return None

        # Update scan count and last_seen
        _threat_col.update_one(
            {"qr_hash": qr_hash},
            {
                "$inc":         {"scan_count": 1, "blocked_count": 1},
                "$set":         {"last_seen": datetime.now(timezone.utc).isoformat()},
            },
        )

        # Increment global blocked count
        _increment_stat("total_blocked", 1)

        return {
            "from_threat_db":       True,
            "blocked":              True,
            "qr_hash":              qr_hash,
            "verdict":              verdict,
            "risk_score":           doc.get("risk_score", 0),
            "qr_type":             doc.get("qr_type", "UNKNOWN"),
            "result_snapshot":      doc.get("result_snapshot", {}),
            "first_seen":           doc.get("first_seen"),
            "last_seen":            datetime.now(timezone.utc).isoformat(),
            "scan_count":           doc.get("scan_count", 0) + 1,
            "blocked_count":        doc.get("blocked_count", 0) + 1,
            "reported_by_users":    doc.get("reported_by_users", 0),
            "report_reasons":       doc.get("report_reasons", []),
            "is_community_flagged": doc.get("is_community_flagged", False),
            "prevention_action":    doc.get("prevention_action", "BLOCKED"),
        }

    except Exception as e:
        print(f"⚠️  Threat DB lookup failed: {e}")
        return None


# ── Save ──────────────────────────────────────────────────────────────────────

def save_threat(qr_data: str, verdict: str, result: dict,
                qr_type: str = "UNKNOWN", prevention_action: str = "NONE"):
    """
    Save or update a QR scan result in the threat database.
    Called after every scan completes.
    """
    if _threat_col is None:
        return

    qr_hash   = hash_qr_content(qr_data)
    now       = datetime.now(timezone.utc).isoformat()
    risk      = result.get("risk_score", 0)
    is_threat = verdict in ("DANGEROUS", "SUSPICIOUS")

    try:
        existing = _threat_col.find_one({"qr_hash": qr_hash})

        if existing:
            # Update existing record
            update = {
                "$inc": {"scan_count": 1},
                "$set": {
                    "last_seen":         now,
                    "verdict":           verdict,
                    "risk_score":        risk,
                    "result_snapshot":   _slim_result(result),
                    "prevention_action": prevention_action,
                },
            }
            if is_threat:
                update["$inc"]["blocked_count"] = 1
            _threat_col.update_one({"qr_hash": qr_hash}, update)
        else:
            # Insert new record
            doc = {
                "qr_hash":              qr_hash,
                "qr_data":              qr_data[:500],  # truncate for storage
                "qr_type":              qr_type,
                "verdict":              verdict,
                "risk_score":           risk,
                "result_snapshot":      _slim_result(result),
                "first_seen":           now,
                "last_seen":            now,
                "scan_count":           1,
                "blocked_count":        1 if is_threat else 0,
                "reported_by_users":    0,
                "report_reasons":       [],
                "is_community_flagged": False,
                "prevention_action":    prevention_action,
            }
            _threat_col.insert_one(doc)

        # Update global stats
        _increment_stat("total_scans", 1)
        if is_threat:
            _increment_stat("total_threats", 1)
            _increment_type_stat(qr_type)
        else:
            _increment_stat("total_safe", 1)

    except Exception as e:
        print(f"⚠️  Threat DB save failed: {e}")


# ── Community Reporting ───────────────────────────────────────────────────────

def report_qr(qr_data: str, reason: str = "") -> dict:
    """
    Allows users to report a QR code as suspicious/malicious.
    If enough reports accumulate, the QR is auto-flagged as community threat.
    """
    if _threat_col is None:
        return {"success": False, "error": "Threat DB not available"}

    qr_hash = hash_qr_content(qr_data)
    now     = datetime.now(timezone.utc).isoformat()

    try:
        existing = _threat_col.find_one({"qr_hash": qr_hash})

        if existing:
            # Update existing — add report
            update = {
                "$inc": {"reported_by_users": 1},
                "$set": {"last_seen": now},
            }
            if reason:
                update["$push"] = {"report_reasons": reason[:200]}

            # Auto-flag as community threat if 3+ reports
            report_count = existing.get("reported_by_users", 0) + 1
            if report_count >= 3:
                update.setdefault("$set", {})
                update["$set"]["is_community_flagged"] = True
                update["$set"]["verdict"]              = "DANGEROUS"
                update["$set"]["prevention_action"]    = "COMMUNITY_BLOCKED"

            _threat_col.update_one({"qr_hash": qr_hash}, update)
        else:
            # Create new entry from user report
            doc = {
                "qr_hash":              qr_hash,
                "qr_data":              qr_data[:500],
                "qr_type":              _detect_type_simple(qr_data),
                "verdict":              "SUSPICIOUS",
                "risk_score":           60,
                "result_snapshot":       {},
                "first_seen":           now,
                "last_seen":            now,
                "scan_count":           0,
                "blocked_count":        0,
                "reported_by_users":    1,
                "report_reasons":       [reason[:200]] if reason else [],
                "is_community_flagged": False,
                "prevention_action":    "USER_REPORTED",
            }
            _threat_col.insert_one(doc)

        _increment_stat("total_reports", 1)

        return {
            "success":      True,
            "qr_hash":      qr_hash,
            "message":      "QR reported successfully. Thank you for protecting the community!",
            "report_count": (existing.get("reported_by_users", 0) + 1) if existing else 1,
        }

    except Exception as e:
        print(f"⚠️  Report QR failed: {e}")
        return {"success": False, "error": str(e)}


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_threat_stats() -> dict:
    """Returns threat database statistics for the dashboard."""
    if _stats_col is None:
        return {"error": "Threat DB not available"}

    try:
        doc = _stats_col.find_one({"_id": "global"}) or {}

        # Also get live counts from threat_cache
        threat_count = _threat_col.count_documents(
            {"verdict": {"$in": ["DANGEROUS", "SUSPICIOUS"]}}
        ) if _threat_col is not None else 0

        total_scans = _threat_col.count_documents({}) if _threat_col is not None else 0

        # Top threats (most scanned dangerous QRs)
        top_threats = []
        if _threat_col is not None:
            cursor = _threat_col.find(
                {"verdict": "DANGEROUS"},
                {"qr_data": 1, "qr_type": 1, "scan_count": 1,
                 "blocked_count": 1, "reported_by_users": 1, "_id": 0}
            ).sort("scan_count", -1).limit(5)
            top_threats = list(cursor)
            # Mask sensitive data in QR content
            for t in top_threats:
                t["qr_data"] = _mask_qr_data(t.get("qr_data", ""))

        return {
            "total_scans":          doc.get("total_scans", 0),
            "total_threats":        doc.get("total_threats", 0),
            "total_blocked":        doc.get("total_blocked", 0),
            "total_safe":           doc.get("total_safe", 0),
            "total_reports":        doc.get("total_reports", 0),
            "threats_in_db":        threat_count,
            "unique_qrs_scanned":   total_scans,
            "threats_by_type":      doc.get("threats_by_type", {}),
            "top_threats":          top_threats,
            "community_protection": doc.get("total_blocked", 0),
            "last_updated":         doc.get("last_updated"),
        }

    except Exception as e:
        print(f"⚠️  Threat stats failed: {e}")
        return {"error": str(e)}


# ── Prevention Actions ────────────────────────────────────────────────────────

def get_prevention_action(qr_type: str, verdict: str, result: dict) -> dict:
    """
    Determines what action to prevent based on QR type and verdict.
    Returns a dict with action type and user-facing message.
    """
    if verdict == "SAFE":
        return {"action": "ALLOW", "message": "No threats detected", "icon": "✅"}

    actions = {
        "URL": {
            "DANGEROUS":  {
                "action":  "BLOCK_URL",
                "message": "⛔ Blocked opening dangerous website. This URL has been flagged as a phishing/malware site.",
                "icon":    "🚫",
            },
            "SUSPICIOUS": {
                "action":  "WARN_URL",
                "message": "⚠️ Warning: This URL shows suspicious characteristics. Proceed with extreme caution.",
                "icon":    "⚠️",
            },
        },
        "UPI": {
            "DANGEROUS":  {
                "action":  "BLOCK_PAYMENT",
                "message": "⛔ Blocked fraudulent UPI payment. This QR code contains scam indicators.",
                "icon":    "🚫",
            },
            "SUSPICIOUS": {
                "action":  "WARN_PAYMENT",
                "message": "⚠️ Warning: Verify this UPI recipient carefully before making any payment.",
                "icon":    "⚠️",
            },
        },
        "WIFI": {
            "DANGEROUS":  {
                "action":  "BLOCK_WIFI",
                "message": "⛔ Blocked auto-connect to dangerous WiFi network. This is an open/insecure network.",
                "icon":    "🚫",
            },
            "SUSPICIOUS": {
                "action":  "WARN_WIFI",
                "message": "⚠️ Warning: This WiFi network may not be secure. Avoid sensitive activities.",
                "icon":    "⚠️",
            },
        },
        "APP": {
            "DANGEROUS":  {
                "action":  "BLOCK_INSTALL",
                "message": "⛔ Blocked installation of potentially malicious app from unknown source.",
                "icon":    "🚫",
            },
            "SUSPICIOUS": {
                "action":  "WARN_INSTALL",
                "message": "⚠️ Warning: This app is from an unverified source. Install at your own risk.",
                "icon":    "⚠️",
            },
        },
        "SMS": {
            "DANGEROUS":  {
                "action":  "BLOCK_SMS",
                "message": "⛔ Blocked suspicious SMS. This message contains phishing indicators.",
                "icon":    "🚫",
            },
            "SUSPICIOUS": {
                "action":  "WARN_SMS",
                "message": "⚠️ Warning: This SMS contains suspicious keywords. Do not share personal information.",
                "icon":    "⚠️",
            },
        },
    }

    type_actions = actions.get(qr_type, {})
    return type_actions.get(verdict, {
        "action":  "WARN_GENERIC",
        "message": f"⚠️ This {qr_type} QR code has been flagged as {verdict.lower()}.",
        "icon":    "⚠️",
    })


# ── Internals ─────────────────────────────────────────────────────────────────

def _slim_result(result: dict) -> dict:
    """Strip large fields from result before storing in threat DB."""
    slim = {}
    keep = [
        "verdict", "risk_score", "qr_type", "qr_data", "url",
        "sandbox_required", "reason", "confidence",
        "is_upi", "prevention_action",
    ]
    for k in keep:
        if k in result:
            slim[k] = result[k]

    # Keep essential analysis fields but not full payloads
    if "analysis" in result:
        a = result["analysis"]
        slim["analysis_summary"] = {
            "ml_phishing":    a.get("ml", {}).get("is_phishing", False),
            "ml_confidence":  a.get("ml", {}).get("confidence", 0),
            "vt_malicious":   a.get("virustotal", {}).get("malicious", 0),
            "gsb_safe":       a.get("google_safe_browsing", {}).get("is_safe", True),
            "domain_new":     a.get("domain", {}).get("is_new", False),
        }

    # Keep UPI-specific data
    for upi_key in ["upi_analysis", "parsed_data"]:
        if upi_key in result:
            upi = result[upi_key]
            if isinstance(upi, dict):
                slim[upi_key] = {
                    k: upi[k] for k in [
                        "upi_id", "payee_name", "platform", "bank_name",
                        "phone_number", "phone_carrier", "risk_level",
                        "amount", "is_merchant_qr", "fraud_flags",
                    ] if k in upi
                }

    return slim


def _increment_stat(field: str, amount: int = 1):
    """Increment a field in the global stats document."""
    if _stats_col is None:
        return
    try:
        _stats_col.update_one(
            {"_id": "global"},
            {
                "$inc": {field: amount},
                "$set": {"last_updated": datetime.now(timezone.utc).isoformat()},
            },
        )
    except Exception:
        pass


def _increment_type_stat(qr_type: str):
    """Increment per-type threat counter."""
    if _stats_col is None:
        return
    try:
        _stats_col.update_one(
            {"_id": "global"},
            {"$inc": {f"threats_by_type.{qr_type}": 1}},
        )
    except Exception:
        pass


def _detect_type_simple(data: str) -> str:
    """Quick QR type detection for reports (no import needed)."""
    d = data.lower().strip()
    if d.startswith("upi://") or ("pa=" in d and "@" in d):
        return "UPI"
    if d.startswith(("http://", "https://")):
        return "URL"
    if d.startswith("wifi:"):
        return "WIFI"
    if d.startswith(("sms:", "smsto:")):
        return "SMS"
    if d.startswith("mailto:"):
        return "EMAIL"
    if d.startswith("tel:"):
        return "PHONE"
    return "TEXT"


def _mask_qr_data(data: str) -> str:
    """Mask sensitive parts of QR data for display in stats."""
    if not data:
        return ""
    # Mask UPI IDs: show first 3 and last 3 chars
    if "pa=" in data.lower():
        pa_match = re.search(r"pa=([^&]+)", data, re.IGNORECASE)
        if pa_match:
            upi_id = pa_match.group(1)
            if len(upi_id) > 6:
                masked = upi_id[:3] + "***" + upi_id[-3:]
                data = data.replace(upi_id, masked)
    # Mask phone numbers
    data = re.sub(r"(\d{3})\d{4}(\d{3})", r"\1****\2", data)
    # Truncate
    return data[:80] + ("..." if len(data) > 80 else "")
