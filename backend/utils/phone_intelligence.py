"""
backend/utils/phone_intelligence.py
Mobile Number Intelligence Engine for SafeScan-Pro
───────────────────────────────────────────────────
Extracts maximum information from a 10-digit Indian mobile number:
  - Telecom operator (Jio, Airtel, Vi, BSNL)
  - Telecom circle / geographic region
  - Number series age (newer = higher risk)
  - Virtual/VoIP number detection
  - Connected UPI app from handle
  - Carrier ↔ UPI handle mismatch detection
  - Risk scoring based on number patterns
"""

import re

# ── Indian Telecom Operator Prefixes (DoT Numbering Plan) ─────────────────
# Source: Department of Telecommunications, India
# Format: first 4 digits → (operator, circle)
# We use first 2-4 digits for operator, and extended prefixes for circles

OPERATOR_BY_PREFIX = {
    # Jio (Reliance) — 6xxx and 7xxx series primarily
    "6000": "Jio", "6001": "Jio", "6002": "Jio", "6003": "Jio", "6004": "Jio",
    "6005": "Jio", "6006": "Jio",
    "7000": "Jio", "7001": "Jio", "7002": "Jio", "7003": "Jio", "7004": "Jio",
    "7005": "Jio", "7006": "Jio", "7007": "Jio", "7008": "Jio", "7009": "Jio",
    "7010": "Jio", "7011": "Jio", "7012": "Jio", "7013": "Jio", "7014": "Jio",
    "7015": "Jio", "7016": "Jio", "7017": "Jio", "7018": "Jio", "7019": "Jio",
    "7020": "Jio", "7021": "Jio", "7022": "Jio", "7023": "Jio",
    # Airtel — 7xxx, 8xxx, 9xxx
    "7042": "Airtel", "7053": "Airtel", "7065": "Airtel",
    "8010": "Airtel", "8013": "Airtel", "8014": "Airtel",
    "8130": "Airtel", "8178": "Airtel", "8182": "Airtel",
    "8191": "Airtel", "8192": "Airtel",
    "9312": "Airtel", "9313": "Airtel", "9350": "Airtel", "9354": "Airtel",
    "9560": "Airtel", "9582": "Airtel", "9650": "Airtel", "9654": "Airtel",
    "9711": "Airtel", "9717": "Airtel", "9810": "Airtel", "9811": "Airtel",
    "9818": "Airtel", "9871": "Airtel", "9873": "Airtel", "9899": "Airtel",
    "9910": "Airtel", "9911": "Airtel", "9953": "Airtel", "9958": "Airtel",
    # Vi (Vodafone Idea)
    "7024": "Vi", "7030": "Vi", "7038": "Vi", "7039": "Vi",
    "7045": "Vi", "7057": "Vi", "7058": "Vi", "7066": "Vi",
    "8080": "Vi", "8082": "Vi", "8087": "Vi", "8097": "Vi",
    "8108": "Vi", "8149": "Vi", "8169": "Vi", "8286": "Vi",
    "8291": "Vi", "8369": "Vi", "8451": "Vi", "8452": "Vi",
    "8454": "Vi", "8459": "Vi", "8530": "Vi", "8552": "Vi",
    "8600": "Vi", "8605": "Vi", "8652": "Vi", "8655": "Vi",
    "8657": "Vi", "8668": "Vi", "8689": "Vi",
    "9004": "Vi", "9029": "Vi", "9004": "Vi",
    "9320": "Vi", "9321": "Vi", "9322": "Vi", "9323": "Vi",
    "9324": "Vi", "9325": "Vi", "9326": "Vi",
    "9619": "Vi", "9620": "Vi", "9637": "Vi", "9638": "Vi",
    "9664": "Vi", "9665": "Vi", "9702": "Vi",
    "9820": "Vi", "9821": "Vi", "9833": "Vi", "9834": "Vi",
    "9860": "Vi", "9867": "Vi", "9869": "Vi", "9870": "Vi",
    "9920": "Vi", "9920": "Vi", "9930": "Vi",
    # BSNL
    "7828": "BSNL", "7837": "BSNL", "7839": "BSNL",
    "8219": "BSNL", "8266": "BSNL", "8278": "BSNL",
    "9401": "BSNL", "9402": "BSNL", "9410": "BSNL",
    "9412": "BSNL", "9413": "BSNL", "9414": "BSNL",
    "9415": "BSNL", "9450": "BSNL", "9451": "BSNL",
    "9452": "BSNL", "9453": "BSNL", "9454": "BSNL",
    "9455": "BSNL", "9456": "BSNL",
}

# ── Telecom Circle Detection (first 3-4 digits → region) ─────────────────
CIRCLE_BY_PREFIX = {
    # Delhi
    "981": "Delhi", "991": "Delhi", "871": "Delhi", "956": "Delhi",
    "965": "Delhi", "931": "Delhi", "958": "Delhi", "813": "Delhi",
    "971": "Delhi", "700": "Delhi",
    # Mumbai
    "982": "Mumbai", "992": "Mumbai", "993": "Mumbai",
    "986": "Mumbai", "902": "Mumbai", "832": "Mumbai",
    "808": "Mumbai", "865": "Mumbai",
    # Maharashtra
    "983": "Maharashtra", "960": "Maharashtra", "963": "Maharashtra",
    "770": "Maharashtra", "860": "Maharashtra",
    # Gujarat
    "979": "Gujarat", "966": "Gujarat", "970": "Gujarat",
    "636": "Gujarat", "776": "Gujarat",
    # Karnataka
    "974": "Karnataka", "996": "Karnataka", "994": "Karnataka",
    "630": "Karnataka", "814": "Karnataka",
    # Tamil Nadu
    "975": "Tamil Nadu", "978": "Tamil Nadu", "995": "Tamil Nadu",
    "634": "Tamil Nadu", "638": "Tamil Nadu",
    # Andhra Pradesh / Telangana
    "939": "AP/Telangana", "984": "AP/Telangana", "944": "AP/Telangana",
    "630": "AP/Telangana", "773": "AP/Telangana",
    # West Bengal / Kolkata
    "983": "West Bengal", "903": "Kolkata", "974": "Kolkata",
    # Uttar Pradesh
    "941": "UP East", "945": "UP East", "950": "UP West",
    "880": "UP East", "789": "UP East",
    # Rajasthan
    "941": "Rajasthan", "929": "Rajasthan", "772": "Rajasthan",
    # Kerala
    "944": "Kerala", "994": "Kerala", "859": "Kerala",
    # Punjab
    "981": "Punjab", "988": "Punjab", "628": "Punjab",
    # Madhya Pradesh
    "989": "MP/CG", "771": "MP/CG", "839": "MP/CG",
    # Bihar / Jharkhand
    "940": "Bihar/Jharkhand", "782": "Bihar/Jharkhand",
    # Assam / NE
    "940": "NE/Assam", "781": "NE/Assam", "636": "NE/Assam",
}

# ── UPI Handle → App / Platform Mapping ──────────────────────────────────
UPI_HANDLE_INFO = {
    "ybl":       {"app": "PhonePe",         "company": "PhonePe Pvt Ltd",         "bank": "Yes Bank"},
    "ibl":       {"app": "PhonePe",         "company": "PhonePe Pvt Ltd",         "bank": "ICICI Bank"},
    "axl":       {"app": "PhonePe",         "company": "PhonePe Pvt Ltd",         "bank": "Axis Bank"},
    "paytm":     {"app": "Paytm",           "company": "One97 Communications",    "bank": "Paytm Payments Bank"},
    "oksbi":     {"app": "SBI Pay / BHIM",  "company": "State Bank of India",     "bank": "SBI"},
    "okaxis":    {"app": "BHIM Axis Pay",   "company": "Axis Bank",               "bank": "Axis Bank"},
    "okicici":   {"app": "iMobile Pay",     "company": "ICICI Bank",              "bank": "ICICI Bank"},
    "okhdfc":    {"app": "HDFC MobileBanking","company": "HDFC Bank",             "bank": "HDFC Bank"},
    "okhdfcbank":{"app": "HDFC MobileBanking","company": "HDFC Bank",             "bank": "HDFC Bank"},
    "apl":       {"app": "Amazon Pay",      "company": "Amazon",                  "bank": "Axis Bank"},
    "ratn":      {"app": "RBL Bank",        "company": "RBL Bank",                "bank": "RBL Bank"},
    "upi":       {"app": "BHIM UPI",        "company": "NPCI",                    "bank": "Multiple"},
    "gpay":      {"app": "Google Pay",      "company": "Google India",            "bank": "Multiple"},
    "jupiter":   {"app": "Jupiter Money",   "company": "Jupiter (Amica)",         "bank": "Federal Bank"},
    "slice":     {"app": "Slice",           "company": "Slice (Quadrillion)",     "bank": "North East SFB"},
    "freecharge":{"app": "Freecharge",      "company": "Axis Bank",               "bank": "Axis Bank"},
    "barodampay":{"app": "Baroda M-Pay",    "company": "Bank of Baroda",          "bank": "Bank of Baroda"},
    "kotak":     {"app": "Kotak App",       "company": "Kotak Mahindra Bank",     "bank": "Kotak Bank"},
    "axisbank":  {"app": "Axis Mobile",     "company": "Axis Bank",               "bank": "Axis Bank"},
    "icici":     {"app": "iMobile Pay",     "company": "ICICI Bank",              "bank": "ICICI Bank"},
    "sbi":       {"app": "SBI YONO",        "company": "State Bank of India",     "bank": "SBI"},
    "hdfcbank":  {"app": "HDFC MobileBanking","company": "HDFC Bank",             "bank": "HDFC Bank"},
    "pnb":       {"app": "PNB ONE",         "company": "Punjab National Bank",    "bank": "PNB"},
    "boi":       {"app": "BOI Mobile",      "company": "Bank of India",           "bank": "Bank of India"},
    "cbin":      {"app": "Central Bank",    "company": "Central Bank of India",   "bank": "Central Bank"},
    "cnrb":      {"app": "Canara ai1",      "company": "Canara Bank",             "bank": "Canara Bank"},
    "idbi":      {"app": "IDBI Go Mobile+", "company": "IDBI Bank",               "bank": "IDBI Bank"},
    "yesbank":   {"app": "Yes Mobile",      "company": "Yes Bank",                "bank": "Yes Bank"},
    "dbs":       {"app": "DBS digibank",    "company": "DBS Bank India",          "bank": "DBS Bank"},
    "federal":   {"app": "FedMobile",       "company": "Federal Bank",            "bank": "Federal Bank"},
    "indus":     {"app": "IndusMobile",     "company": "IndusInd Bank",           "bank": "IndusInd Bank"},
    "kbl":       {"app": "KBL Mobile Plus", "company": "Karnataka Bank",          "bank": "Karnataka Bank"},
    "cub":       {"app": "CUB M-Banking",   "company": "City Union Bank",         "bank": "City Union Bank"},
    "rbl":       {"app": "RBL MoBank",      "company": "RBL Bank",                "bank": "RBL Bank"},
    "dlb":       {"app": "Dhanlaxmi Bank",  "company": "Dhanlaxmi Bank",          "bank": "Dhanlaxmi Bank"},
    "idfcfirst": {"app": "IDFC FIRST",      "company": "IDFC First Bank",         "bank": "IDFC First Bank"},
    "aubank":    {"app": "AU 0101",         "company": "AU Small Finance Bank",   "bank": "AU SFB"},
    "equitas":   {"app": "Equitas Mobile",  "company": "Equitas SFB",             "bank": "Equitas SFB"},
    "fi":        {"app": "Fi Money",        "company": "epiFi Technologies",      "bank": "Federal Bank"},
    "tapicici":  {"app": "Tap by ICICI",    "company": "ICICI Bank",              "bank": "ICICI Bank"},
    "waaxis":    {"app": "WhatsApp Pay",    "company": "Meta / WhatsApp",         "bank": "Axis Bank"},
    "wahdfcbank":{"app": "WhatsApp Pay",    "company": "Meta / WhatsApp",         "bank": "HDFC Bank"},
    "wasbi":     {"app": "WhatsApp Pay",    "company": "Meta / WhatsApp",         "bank": "SBI"},
    "waicici":   {"app": "WhatsApp Pay",    "company": "Meta / WhatsApp",         "bank": "ICICI Bank"},
}

# ── Virtual / VoIP Number Ranges ─────────────────────────────────────────
VIRTUAL_PREFIXES = [
    "6291", "6292",  # Known virtual/VoIP
    "6370", "6371",  # Virtual SIM providers
    "7428", "7429",  # eSIM / virtual
]

# ── Number Series Allocation Timeline (newer = higher fraud risk) ────────
# Rough allocation: 9xxx (1990s), 8xxx (2000s), 7xxx (2010s), 6xxx (2016+)
SERIES_AGE = {
    "9": {"era": "1995–2005",  "label": "Legacy series",    "age_risk": "LOW",    "years": 20},
    "8": {"era": "2005–2014",  "label": "Mid-era series",   "age_risk": "LOW",    "years": 12},
    "7": {"era": "2014–2018",  "label": "Modern series",    "age_risk": "MEDIUM", "years": 8},
    "6": {"era": "2016–Present","label": "Newest series",   "age_risk": "MEDIUM", "years": 5},
}


# ── Main Intelligence Function ───────────────────────────────────────────

def analyze_phone_number(phone: str, upi_handle: str = "") -> dict:
    """
    Extracts maximum intelligence from a 10-digit Indian mobile number.
    
    Args:
        phone: 10-digit mobile number (e.g., "9876543210")
        upi_handle: UPI handle after @ (e.g., "ybl", "paytm")
    
    Returns:
        Dict with operator, circle, risk signals, connected apps, etc.
    """
    phone = re.sub(r"[^0-9]", "", phone)
    
    # Strip country code if present
    if len(phone) == 12 and phone.startswith("91"):
        phone = phone[2:]
    elif len(phone) == 13 and phone.startswith("+91"):
        phone = phone[3:]
    
    if len(phone) != 10 or not re.match(r"^[6-9]\d{9}$", phone):
        return {"valid": False, "error": "Not a valid 10-digit Indian mobile number"}
    
    result = {
        "valid":          True,
        "number":         phone,
        "formatted":      f"+91 {phone[:5]} {phone[5:]}",
        "masked":         f"+91 {phone[:3]}****{phone[7:]}",
        "country":        "India",
        "country_code":   "+91",
    }
    
    # ── 1. Telecom Operator ───────────────────────────────────────────
    prefix4 = phone[:4]
    prefix3 = phone[:3]
    prefix2 = phone[:2]
    
    operator = OPERATOR_BY_PREFIX.get(prefix4, None)
    if not operator:
        # Fallback: broad prefix mapping
        broad_map = {
            "60": "Jio", "61": "Jio", "62": "Jio", "63": "Jio",
            "64": "Jio", "65": "Jio", "66": "Vi/Jio",
            "70": "Jio", "73": "Airtel/Jio", "74": "Airtel/Vi",
            "75": "Jio/Vi", "76": "Jio/Vi", "77": "Airtel/BSNL",
            "78": "Jio/BSNL", "79": "Airtel/Jio",
            "80": "Vi/Airtel", "81": "Airtel/Jio", "82": "BSNL/Airtel",
            "83": "Jio/Vi", "84": "Vi", "85": "Jio/Vi",
            "86": "Vi/Jio", "87": "Airtel/Jio", "88": "Airtel/Jio",
            "89": "Airtel/Vi",
            "90": "Vi", "91": "Airtel/Vi", "92": "Airtel/Vi",
            "93": "Airtel/Vi", "94": "BSNL/Airtel", "95": "Airtel/Vi",
            "96": "Jio/Vi", "97": "Airtel/Vi", "98": "Airtel/Vi",
            "99": "Airtel/Vi",
        }
        operator = broad_map.get(prefix2, "Unknown")
    
    result["operator"] = operator
    
    # ── 2. Telecom Circle / Region ────────────────────────────────────
    circle = CIRCLE_BY_PREFIX.get(prefix3, None)
    if not circle:
        circle = CIRCLE_BY_PREFIX.get(prefix4, "Unknown Region")
    result["telecom_circle"] = circle
    result["region"]         = circle
    
    # ── 3. Number Series Age ──────────────────────────────────────────
    first_digit   = phone[0]
    series_info   = SERIES_AGE.get(first_digit, {"era": "Unknown", "label": "Unknown", "age_risk": "MEDIUM", "years": 0})
    result["number_series"] = {
        "first_digit":    first_digit,
        "series":         f"{first_digit}xxx",
        "allocation_era": series_info["era"],
        "label":          series_info["label"],
        "approx_age":     f"~{series_info['years']}+ years",
        "age_risk":       series_info["age_risk"],
    }
    
    # ── 4. Virtual / VoIP Detection ───────────────────────────────────
    is_virtual = prefix4 in VIRTUAL_PREFIXES
    result["is_virtual_number"] = is_virtual
    if is_virtual:
        result["virtual_warning"] = "This number may be a virtual/VoIP number — commonly used for temporary or anonymous communication"
    
    # ── 5. Connected UPI App / Platform ───────────────────────────────
    handle_lower = upi_handle.lower().strip() if upi_handle else ""
    upi_info     = UPI_HANDLE_INFO.get(handle_lower, None)
    
    if upi_info:
        result["connected_upi"] = {
            "handle":       f"@{handle_lower}",
            "app":          upi_info["app"],
            "company":      upi_info["company"],
            "linked_bank":  upi_info["bank"],
        }
    else:
        result["connected_upi"] = {
            "handle":       f"@{handle_lower}" if handle_lower else "Unknown",
            "app":          "Unknown / Direct Bank App",
            "company":      "Unknown",
            "linked_bank":  f"Unknown handle: @{handle_lower}" if handle_lower else "N/A",
        }
    
    # ── 6. Carrier ↔ UPI Handle Mismatch Detection ───────────────────
    mismatch_signals = []
    if upi_info and operator and "/" not in operator:
        # Check if carrier is unusual for the UPI platform
        # e.g., BSNL number on PhonePe is fine, but worth noting
        bank = upi_info.get("bank", "")
        # Some handles are bank-specific — if the number's carrier
        # is from a different bank's mobile service, note it
        if handle_lower in ("paytm",) and "BSNL" in operator:
            mismatch_signals.append({
                "signal":   "Unusual carrier-app combination",
                "detail":   f"{operator} number using {upi_info['app']} — uncommon but valid",
                "severity": "LOW",
            })
    
    result["mismatch_signals"] = mismatch_signals
    
    # ── 7. Risk Intelligence Summary ──────────────────────────────────
    risk_signals = []
    risk_score   = 0
    
    # Newer number series
    if series_info["age_risk"] == "MEDIUM":
        risk_signals.append({
            "signal":   "Newer number series",
            "detail":   f"{series_info['series']} series ({series_info['era']}) — newer allocations see higher fraud rates",
            "severity": "LOW",
            "score":    5,
        })
        risk_score += 5
    
    # Virtual number
    if is_virtual:
        risk_signals.append({
            "signal":   "Virtual/VoIP number detected",
            "detail":   "This number is from a known virtual SIM range — often used for anonymous transactions",
            "severity": "HIGH",
            "score":    25,
        })
        risk_score += 25
    
    # Unknown operator
    if operator == "Unknown":
        risk_signals.append({
            "signal":   "Unrecognised operator",
            "detail":   f"Prefix {prefix4} does not match known Indian carriers",
            "severity": "MEDIUM",
            "score":    10,
        })
        risk_score += 10
    
    # Repeated digits pattern (e.g., 9999999999)
    if len(set(phone)) <= 3:
        risk_signals.append({
            "signal":   "Suspicious number pattern",
            "detail":   f"Number {phone} has very few unique digits — possibly fake",
            "severity": "HIGH",
            "score":    30,
        })
        risk_score += 30
    
    # Sequential digits (e.g., 1234567890)
    if phone in ("6789012345", "7890123456", "8901234567", "9012345678", "9876543210"):
        risk_signals.append({
            "signal":   "Sequential number pattern",
            "detail":   "This appears to be a test/fake sequential number",
            "severity": "HIGH",
            "score":    35,
        })
        risk_score += 35
    
    result["risk_signals"] = risk_signals
    result["phone_risk_score"] = min(risk_score, 100)
    result["phone_risk_level"] = (
        "HIGH"   if risk_score >= 25 else
        "MEDIUM" if risk_score >= 10 else
        "LOW"
    )
    
    # ── 8. Summary for display ────────────────────────────────────────
    summary_parts = [f"📱 {result['formatted']}"]
    summary_parts.append(f"📡 Operator: {operator}")
    if circle and circle != "Unknown Region":
        summary_parts.append(f"📍 Region: {circle}")
    summary_parts.append(f"📅 Series: {series_info['label']} ({series_info['era']})")
    if upi_info:
        summary_parts.append(f"💳 UPI App: {upi_info['app']} ({upi_info['bank']})")
    if is_virtual:
        summary_parts.append("⚠️ Virtual/VoIP number detected")
    
    result["summary"] = " | ".join(summary_parts)
    result["summary_lines"] = summary_parts
    
    return result
