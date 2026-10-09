"""
backend/utils/non_url_qr_analyzer.py
Enhanced UPI analyzer with agency-level intelligence:
  - Bank + branch + IFSC via Razorpay API
  - Device fingerprint estimation from QR metadata
  - Transaction pattern risk scoring
  - GSTIN / business registration detection
  - Branch geolocation coordinates
  - QR creation timestamp estimation
  - Fraud signal severity scoring
"""

import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote
from .phone_intelligence import analyze_phone_number

try:
    import urllib.request
except ImportError:
    urllib = None

# ── UPI handle → bank info ─────────────────────────────────────────────────────
UPI_BANK_MAP = {
    "okicici":     {"name": "ICICI Bank",               "platform": "Google Pay",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-1080",      "website": "https://www.icicibank.com",        "regulator": "RBI"},
    "okhdfcbank":  {"name": "HDFC Bank",                "platform": "Google Pay",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-202-6161",  "website": "https://www.hdfcbank.com",         "regulator": "RBI"},
    "okaxis":      {"name": "Axis Bank",                "platform": "Google Pay",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "oksbi":       {"name": "State Bank of India",      "platform": "Google Pay",      "type": "Public Sector (PSU)", "hq": "Mumbai, Maharashtra",    "care": "1800-425-3800",  "website": "https://www.sbi.co.in",            "regulator": "RBI"},
    "ybl":         {"name": "Yes Bank",                 "platform": "PhonePe",         "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-1200",      "website": "https://www.yesbank.in",           "regulator": "RBI"},
    "axl":         {"name": "Axis Bank",                "platform": "PhonePe",         "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "ibl":         {"name": "IDFC First Bank",          "platform": "PhonePe",         "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-4332",  "website": "https://www.idfcfirstbank.com",    "regulator": "RBI"},
    "paytm":       {"name": "Paytm Payments Bank",      "platform": "Paytm",           "type": "Payments Bank",       "hq": "Noida, Uttar Pradesh",   "care": "0120-4456-456",  "website": "https://www.paytmbank.com",        "regulator": "RBI"},
    "upi":         {"name": "NPCI / BHIM",              "platform": "BHIM",            "type": "Public (NPCI)",       "hq": "Mumbai, Maharashtra",    "care": "1800-120-1740",  "website": "https://www.bhimupi.org.in",       "regulator": "NPCI"},
    "icici":       {"name": "ICICI Bank",               "platform": "iMobile Pay",     "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-1080",      "website": "https://www.icicibank.com",        "regulator": "RBI"},
    "hdfcbank":    {"name": "HDFC Bank",                "platform": "HDFC NetBanking", "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-202-6161",  "website": "https://www.hdfcbank.com",         "regulator": "RBI"},
    "sbi":         {"name": "State Bank of India",      "platform": "YONO SBI",        "type": "Public Sector (PSU)", "hq": "Mumbai, Maharashtra",    "care": "1800-425-3800",  "website": "https://www.sbi.co.in",            "regulator": "RBI"},
    "axisbank":    {"name": "Axis Bank",                "platform": "Axis Mobile",     "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "kotak":       {"name": "Kotak Mahindra Bank",      "platform": "Kotak Mobile",    "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1860-266-2666",  "website": "https://www.kotak.com",            "regulator": "RBI"},
    "indus":       {"name": "IndusInd Bank",            "platform": "IndusMobile",     "type": "Private Sector",      "hq": "Pune, Maharashtra",      "care": "1860-267-7777",  "website": "https://www.indusind.com",         "regulator": "RBI"},
    "pnb":         {"name": "Punjab National Bank",     "platform": "PNB ONE",         "type": "Public Sector (PSU)", "hq": "New Delhi",              "care": "1800-180-2222",  "website": "https://www.pnbindia.in",          "regulator": "RBI"},
    "boi":         {"name": "Bank of India",            "platform": "BOI Mobile",      "type": "Public Sector (PSU)", "hq": "Mumbai, Maharashtra",    "care": "1800-220-229",   "website": "https://www.bankofindia.co.in",    "regulator": "RBI"},
    "bob":         {"name": "Bank of Baroda",           "platform": "Baroda Pay",      "type": "Public Sector (PSU)", "hq": "Vadodara, Gujarat",      "care": "1800-102-4455",  "website": "https://www.bankofbaroda.in",      "regulator": "RBI"},
    "union":       {"name": "Union Bank of India",      "platform": "Union Bank",      "type": "Public Sector (PSU)", "hq": "Mumbai, Maharashtra",    "care": "1800-22-2244",   "website": "https://www.unionbankofindia.co.in","regulator": "RBI"},
    "federal":     {"name": "Federal Bank",             "platform": "FedMobile",       "type": "Private Sector",      "hq": "Aluva, Kerala",          "care": "1800-425-1199",  "website": "https://www.federalbank.co.in",    "regulator": "RBI"},
    "rbl":         {"name": "RBL Bank",                 "platform": "RBL MoBank",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-121-9050",  "website": "https://www.rblbank.com",          "regulator": "RBI"},
    "cnrb":        {"name": "Canara Bank",              "platform": "Canara ai1",      "type": "Public Sector (PSU)", "hq": "Bangalore, Karnataka",   "care": "1800-425-0018",  "website": "https://canarabank.com",           "regulator": "RBI"},
    "idbi":        {"name": "IDBI Bank",                "platform": "IDBI GO Mobile",  "type": "Public Sector (PSU)", "hq": "Mumbai, Maharashtra",    "care": "1800-200-1947",  "website": "https://www.idbibank.in",          "regulator": "RBI"},
    "yesbank":     {"name": "Yes Bank",                 "platform": "Yes Pay",         "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-1200",      "website": "https://www.yesbank.in",           "regulator": "RBI"},
    "apl":         {"name": "Axis Bank",                "platform": "Amazon Pay",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "waaxis":      {"name": "Axis Bank",                "platform": "WhatsApp Pay",    "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "mbk":         {"name": "Kotak Mahindra Bank",      "platform": "Mobikwik",        "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1860-266-2666",  "website": "https://www.kotak.com",            "regulator": "RBI"},
    "freecharge":  {"name": "Axis Bank",                "platform": "FreeCharge",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "kaypay":      {"name": "Karnataka Bank",           "platform": "KayPay",          "type": "Private Sector",      "hq": "Mangalore, Karnataka",   "care": "1800-425-1444",  "website": "https://www.karnatakabank.com",    "regulator": "RBI"},
    "jupiteraxis": {"name": "Axis Bank",                "platform": "Jupiter",         "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
    "fifederal":   {"name": "Federal Bank",             "platform": "Fi Money",        "type": "Private Sector",      "hq": "Aluva, Kerala",          "care": "1800-425-1199",  "website": "https://www.federalbank.co.in",    "regulator": "RBI"},
    "rarejwl":     {"name": "Jana Small Finance Bank",  "platform": "CRED",            "type": "Small Finance Bank",  "hq": "Bangalore, Karnataka",   "care": "1800-103-9990",  "website": "https://www.janabank.com",         "regulator": "RBI"},
    "yesbankltd":  {"name": "Yes Bank",                 "platform": "Amazon Pay",      "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-1200",      "website": "https://www.yesbank.in",           "regulator": "RBI"},
    "slicepay":    {"name": "North East Small Finance", "platform": "Slice",           "type": "Small Finance Bank",  "hq": "Guwahati, Assam",        "care": "1800-212-2456",  "website": "https://sliceit.com",              "regulator": "RBI"},
    "naviaxis":    {"name": "Axis Bank",                "platform": "Navi",            "type": "Private Sector",      "hq": "Mumbai, Maharashtra",    "care": "1800-419-5555",  "website": "https://www.axisbank.com",         "regulator": "RBI"},
}

# ── Carrier detection ──────────────────────────────────────────────────────────
def get_carrier(phone: str) -> str:
    if not phone or len(phone) < 4:
        return "Unknown"
    p = phone.lstrip("+91").lstrip("0")[:4]
    if p[:2] in ["94","95","96","97","98","99","90","91","92","93"]: return "Airtel"
    if p[:2] in ["70","71","72","73","74","75","76","77","78","79"]: return "Vodafone Idea (Vi)"
    if p[:2] in ["62","63","64","65","66","68","69","80","81","82","83","84","85","86","87","88","89"]: return "Jio"
    if p[:2] in ["60","61"]: return "BSNL"
    return "Unknown"

# ── IFSC branch + geo lookup ───────────────────────────────────────────────────
def fetch_branch_by_ifsc(ifsc: str) -> dict:
    try:
        url = f"https://ifsc.razorpay.com/{ifsc.upper()}"
        req = urllib.request.urlopen(url, timeout=6)
        d   = json.loads(req.read().decode())

        # Build Google Maps link from address
        address = d.get("ADDRESS", "")
        city    = d.get("CITY", "")
        state   = d.get("STATE", "")
        maps_query = urllib.request.quote(f"{address} {city} {state} India")
        maps_link  = f"https://maps.google.com/?q={maps_query}"

        return {
            "branch_name":       d.get("BRANCH", ""),
            "branch_address":    d.get("ADDRESS", ""),
            "branch_city":       d.get("CITY", ""),
            "branch_state":      d.get("STATE", ""),
            "branch_contact":    d.get("CONTACT", ""),
            "micr_code":         d.get("MICR", ""),
            "upi_supported":     d.get("UPI",  False),
            "imps_supported":    d.get("IMPS", False),
            "rtgs_supported":    d.get("RTGS", False),
            "neft_supported":    d.get("NEFT", False),
            "branch_maps_link":  maps_link,
            "branch_maps_query": f"{address}, {city}, {state}",
        }
    except Exception:
        return {}

# ── Device fingerprint estimation from QR string ──────────────────────────────
def estimate_device_fingerprint(raw_data: str) -> dict:
    """
    Estimates which platform/device generated the QR based on:
    - Parameter ordering (Google Pay uses specific order)
    - Field presence / naming conventions
    - Encoding style (+ vs %20, case sensitivity)
    """
    raw_lower = raw_data.lower()
    platform_hint = "Unknown"
    app_version   = "Unknown"
    os_hint       = "Unknown"

    # Google Pay — uses specific param order: pa, pn, mc, tid, tr, tn, am, mam, cu
    if "googl" in raw_lower or ("pa=" in raw_lower and "tid=" in raw_lower and "tr=" in raw_lower):
        platform_hint = "Google Pay (GPay)"
        os_hint       = "Android (likely)"

    # PhonePe — uses psp field or specific encoding
    elif "phonepe" in raw_lower or ("pa=" in raw_lower and "psp=" in raw_lower):
        platform_hint = "PhonePe"
        os_hint       = "Android (likely)"

    # Paytm — often includes paytm in pa field
    elif "paytm" in raw_lower:
        platform_hint = "Paytm"
        os_hint       = "Android / iOS"

    # BHIM — minimal fields, no mc/tid
    elif raw_lower.startswith("upi://pay") and "mc=" not in raw_lower and "tid=" not in raw_lower:
        platform_hint = "BHIM / Direct Bank App"
        os_hint       = "Android (likely)"

    # Merchant terminal / PoS device
    elif "tid=" in raw_lower and "mid=" in raw_lower:
        platform_hint = "Merchant PoS Terminal"
        os_hint       = "Embedded / Android"
        app_version   = "Terminal-generated"

    # QR has + encoding (common in older Android apps)
    if "+" in raw_data and "%20" not in raw_data:
        os_hint = "Android (legacy encoding)"
    elif "%20" in raw_data:
        os_hint = "iOS / Modern Android"

    # Compute a fingerprint hash of the QR structure (not the values)
    structural_key = re.sub(r"=[^&]+", "=*", raw_data)
    fp_hash = hashlib.md5(structural_key.encode()).hexdigest()[:12]

    return {
        "platform_hint":      platform_hint,
        "os_hint":            os_hint,
        "app_version_hint":   app_version,
        "qr_structure_hash":  fp_hash,
        "encoding_style":     "URL-encoded (+)" if "+" in raw_data else "Percent-encoded (%20)" if "%20" in raw_data else "Plain",
        "note": "Fingerprint estimated from QR encoding patterns — not cryptographically verified"
    }

# ── QR creation timestamp estimation ──────────────────────────────────────────
def estimate_qr_timestamp(raw_data: str) -> dict:
    """
    Attempts to extract or estimate when the QR was created.
    Some UPI apps embed tid (transaction ID) with timestamp prefix.
    """
    result = {
        "scan_time":     datetime.now(timezone.utc).isoformat(),
        "tid_extracted": None,
        "timestamp_in_tid": None,
        "age_estimate":  "Unknown — no timestamp in QR data",
    }

    # Extract tid (transaction ID) — sometimes encodes epoch timestamp
    tid_match = re.search(r"tid=([^&]+)", raw_data, re.IGNORECASE)
    if tid_match:
        tid = tid_match.group(1)
        result["tid_extracted"] = tid

        # Some apps prefix tid with epoch millis (13 digits)
        epoch_match = re.search(r"(\d{13})", tid)
        if epoch_match:
            try:
                ts  = int(epoch_match.group(1)) / 1000
                dt  = datetime.fromtimestamp(ts, tz=timezone.utc)
                age = datetime.now(timezone.utc) - dt
                result["timestamp_in_tid"] = dt.isoformat()
                days = age.days
                result["age_estimate"] = (
                    f"Created today ({int(age.seconds/3600)}h ago)" if days == 0
                    else f"Created {days} day(s) ago ({dt.strftime('%d %b %Y')})"
                )
            except Exception:
                pass

    return result

# ── Transaction pattern risk ───────────────────────────────────────────────────
def analyse_transaction_risk(upi_id: str, amount: str, note: str, is_merchant: bool) -> dict:
    """
    Scores transaction risk based on:
    - Amount thresholds
    - Note / description keywords
    - Merchant vs personal QR
    - Round-number patterns (common in scams)
    """
    risk_signals = []
    score = 0

    try:
        amt = float(amount) if amount else 0
    except Exception:
        amt = 0

    # Amount risk
    if amt > 0:
        if amt > 100000:
            risk_signals.append({"signal": "Extremely large amount", "severity": "HIGH",   "detail": f"₹{amt:,.0f} exceeds ₹1,00,000"})
            score += 40
        elif amt > 10000:
            risk_signals.append({"signal": "Large pre-filled amount", "severity": "HIGH",  "detail": f"₹{amt:,.0f} — verify recipient"})
            score += 25
        elif amt > 5000 and not is_merchant:
            # Only flag medium amounts on PERSONAL (non-merchant) QRs
            risk_signals.append({"signal": "Pre-set amount on personal QR", "severity": "MEDIUM","detail": f"₹{amt:,.0f} — verify recipient"})
            score += 10
        elif amt > 0 and is_merchant:
            # Merchant QR with any amount is NORMAL business behavior
            risk_signals.append({"signal": "Pre-set amount",          "severity": "LOW",  "detail": f"₹{amt:,.0f} — merchant QR with price"})
            score += 0  # no risk for merchant QR with amount
        elif amt > 0:
            # Small amount on personal QR — note it but LOW severity
            risk_signals.append({"signal": "Pre-set amount",          "severity": "LOW",  "detail": f"₹{amt:,.0f} — verify recipient"})
            score += 3

        # Round number pattern (scam indicator — only significant for large amounts)
        if amt % 1000 == 0 and amt > 5000:
            risk_signals.append({"signal": "Round number amount",     "severity": "LOW",   "detail": "Large round amounts are common in scam QRs"})
            score += 5

    # Note keywords
    suspicious_note_keywords = [
        ("otp", "HIGH", "OTP in note — banks never ask for this"),
        ("pin", "HIGH", "PIN in note — never share"),
        ("password", "HIGH", "Password in note — never share"),
        ("refund", "MEDIUM", "Refund scam pattern"),
        ("prize", "HIGH", "Prize/lottery scam pattern"),
        ("lottery", "HIGH", "Prize/lottery scam pattern"),
        ("win", "MEDIUM", "Win/reward scam pattern"),
        ("tax", "MEDIUM", "Tax refund scam pattern"),
        ("government", "MEDIUM", "Impersonating government"),
        ("rbi", "HIGH", "Impersonating RBI — never legitimate"),
        ("income", "MEDIUM", "Income tax scam pattern"),
        ("urgent", "MEDIUM", "Urgency pressure tactic"),
        ("blocked", "MEDIUM", "Account blocked scam pattern"),
        ("verify", "MEDIUM", "Verification scam pattern"),
    ]
    note_lower = (note or "").lower()
    for kw, severity, detail in suspicious_note_keywords:
        if kw in note_lower:
            risk_signals.append({"signal": f"Keyword: '{kw}'", "severity": severity, "detail": detail})
            score += 30 if severity == "HIGH" else 15

    # Personal QR with large amount is riskier than merchant
    if not is_merchant and amt > 5000:
        risk_signals.append({"signal": "Personal QR large amount", "severity": "MEDIUM",
                              "detail": "Personal (non-merchant) QR with large pre-set amount is suspicious"})
        score += 10

    return {
        "transaction_risk_score": min(score, 100),
        "transaction_risk_level": "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW",
        "risk_signals":           risk_signals,
        "amount_inr":             f"₹{amt:,.2f}" if amt > 0 else "Not specified",
        "is_merchant_transaction": is_merchant,
    }

# ── GSTIN detection ────────────────────────────────────────────────────────────
def detect_gstin(upi_id: str, note: str, raw_data: str) -> dict:
    """
    Detects GSTIN (business tax registration) embedded in QR data.
    Pattern: 2-digit state code + 10-char PAN + 1Z + 1-alphanumeric + 1-check digit
    """
    combined = f"{upi_id} {note} {raw_data}"
    gstin_pattern = r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"
    matches = re.findall(gstin_pattern, combined.upper())

    if matches:
        gstin = matches[0]
        state_code = int(gstin[:2])
        STATE_MAP = {
            1:"Jammu & Kashmir",2:"Himachal Pradesh",3:"Punjab",4:"Chandigarh",
            5:"Uttarakhand",6:"Haryana",7:"Delhi",8:"Rajasthan",9:"Uttar Pradesh",
            10:"Bihar",11:"Sikkim",12:"Arunachal Pradesh",13:"Nagaland",14:"Manipur",
            15:"Mizoram",16:"Tripura",17:"Meghalaya",18:"Assam",19:"West Bengal",
            20:"Jharkhand",21:"Odisha",22:"Chhattisgarh",23:"Madhya Pradesh",
            24:"Gujarat",27:"Maharashtra",29:"Karnataka",30:"Goa",32:"Kerala",
            33:"Tamil Nadu",36:"Telangana",37:"Andhra Pradesh",
        }
        return {
            "gstin_found":        True,
            "gstin":              gstin,
            "gstin_state":        STATE_MAP.get(state_code, f"State code {state_code}"),
            "gstin_pan_embedded": gstin[2:12],
            "business_type":      "Registered GST Business (B2B/B2C)",
            "verification_url":   f"https://www.mastersindia.co/gst-number-search/?gstin={gstin}",
        }
    return {"gstin_found": False, "gstin": None}

# ── Parse full UPI QR ──────────────────────────────────────────────────────────
def parse_upi(data: str) -> dict:
    info = {
        # Identity
        "upi_id": "", "payee_name": "", "amount": "", "currency": "INR",
        "transaction_note": "", "merchant_code": "", "is_merchant_qr": False,
        "platform": "Unknown",
        # Bank
        "bank_name": "", "bank_type": "", "bank_headquarters": "",
        "bank_regulator": "Reserve Bank of India (RBI)",
        "bank_customer_care": "", "bank_website": "",
        # Branch
        "ifsc_code": "", "branch_name": "", "branch_address": "",
        "branch_city": "", "branch_state": "", "branch_contact": "",
        "micr_code": "", "upi_supported": None, "imps_supported": None,
        "rtgs_supported": None, "neft_supported": None,
        "branch_maps_link": "", "branch_maps_query": "",
        # Phone
        "phone_number": "", "phone_formatted": "", "phone_carrier": "",
        # Agency intel
        "device_fingerprint": {},
        "qr_timestamp": {},
        "transaction_risk": {},
        "gstin_info": {},
        # Fraud
        "risk_level": "LOW", "fraud_flags": [],
    }

    try:
        raw = data
        if raw.startswith("upi://"):  raw = raw[6:]
        if raw.startswith("pay?"):    raw = raw[4:]

        params = {}
        for part in raw.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k.lower().strip()] = v.strip()

        upi_id = params.get("pa", "")
        payee  = params.get("pn", "").replace("+", " ")
        amount = params.get("am", "")
        currency = params.get("cu", "INR")
        note   = params.get("tn", "").replace("+", " ")
        mc     = params.get("mc", "")

        info.update({
            "upi_id": upi_id, "payee_name": payee, "amount": amount,
            "currency": currency, "transaction_note": note,
            "merchant_code": mc, "is_merchant_qr": bool(mc),
        })

        # Bank from handle
        handle = upi_id.split("@")[-1].lower() if "@" in upi_id else ""
        bank   = UPI_BANK_MAP.get(handle, {})
        if bank:
            info["platform"]           = bank.get("platform", "Unknown")
            info["bank_name"]          = bank.get("name", "")
            info["bank_type"]          = bank.get("type", "")
            info["bank_headquarters"]  = bank.get("hq", "")
            info["bank_customer_care"] = bank.get("care", "")
            info["bank_website"]       = bank.get("website", "")
            info["bank_regulator"]     = bank.get("regulator", "RBI")
        else:
            info["platform"]  = "Unknown / Direct Bank App"
            info["bank_name"] = f"Unrecognised handle: @{handle}"

        # Phone number extraction — if part before @ is 10 digits starting with 6-9
        local_part = upi_id.split("@")[0] if "@" in upi_id else upi_id
        if re.match(r"^[6-9]\d{9}$", local_part):
            info["phone_number"]     = local_part
            info["phone_formatted"]  = f"+91 {local_part[:5]} {local_part[5:]}"
            info["phone_carrier"]    = get_carrier(local_part)
            info["is_mobile_linked"] = True

            # Full phone intelligence analysis
            phone_intel = analyze_phone_number(local_part, handle)
            info["phone_intelligence"] = phone_intel
        else:
            info["is_mobile_linked"] = False
            info["phone_intelligence"] = None

        # IFSC from UPI ID or note
        ifsc_match = re.search(r"[A-Z]{4}0[A-Z0-9]{6}", (upi_id + " " + note).upper())
        if ifsc_match:
            ifsc = ifsc_match.group(0)
            info["ifsc_code"] = ifsc
            branch = fetch_branch_by_ifsc(ifsc)
            info.update(branch)

        # ── Agency-level intelligence ──────────────────────────────────────────

        # 1. Device fingerprint
        info["device_fingerprint"] = estimate_device_fingerprint(data)

        # 2. QR timestamp estimation
        info["qr_timestamp"] = estimate_qr_timestamp(data)

        # 3. Transaction risk scoring
        info["transaction_risk"] = analyse_transaction_risk(
            upi_id, amount, note, bool(mc)
        )

        # 4. GSTIN detection
        info["gstin_info"] = detect_gstin(upi_id, note, data)

        # ── Fraud flags ────────────────────────────────────────────────────────
        flags = []

        if amount:
            try:
                amt = float(amount)
                if amt > 50000:
                    flags.append({"severity": "HIGH",   "message": f"Very large pre-filled amount: ₹{amt:,.0f}"})
                elif amt > 10000 and not bool(mc):
                    # Large amount on PERSONAL QR (no merchant code) is suspicious
                    flags.append({"severity": "MEDIUM", "message": f"Large amount ₹{amt:,.0f} on personal QR — verify recipient"})
                # Merchant QR with normal amount = no flag (that's how shops work)
            except Exception:
                pass

        suspicious_payees = ["prize", "lottery", "win", "reward", "refund",
                             "gov", "government", "bank", "rbi", "income tax", "helpdesk"]
        if any(s in payee.lower() for s in suspicious_payees):
            flags.append({"severity": "HIGH", "message": f"Suspicious payee name: '{payee}'"})

        # Impersonation detection — "SBI Refund", "RBI Cashback", "HDFC Support" etc.
        impersonation_patterns = [
            (r"\b(sbi|hdfc|icici|axis|kotak|pnb|bob|boi|rbi|npci)\b", "Bank/Regulator"),
            (r"\b(refund|cashback|credit|bonus|subsidy|compensation)\b", "Financial bait"),
            (r"\b(police|army|court|ministry|department|officer)\b", "Government impersonation"),
            (r"\b(customer\s*care|support|helpline|helpdesk|service\s*center)\b", "Support impersonation"),
        ]
        payee_lower = payee.lower()
        for pattern, label in impersonation_patterns:
            if re.search(pattern, payee_lower):
                flags.append({"severity": "HIGH", "message": f"Possible {label} impersonation in payee: '{payee}'"})
                break

        if not bank:
            flags.append({"severity": "MEDIUM", "message": f"Unknown bank handle @{handle} — could not verify"})

        if note and any(k in note.lower() for k in ["otp", "pin", "password", "cvv"]):
            flags.append({"severity": "HIGH", "message": "Note contains sensitive keyword (OTP/PIN/CVV)"})

        # Personal QR with mobile number and large amount — common scam vector
        if info.get("is_mobile_linked") and not bool(mc):
            try:
                a = float(amount) if amount else 0
                if a > 5000:
                    flags.append({"severity": "HIGH", "message": f"Personal mobile-linked QR with large amount ₹{a:,.0f} — high scam risk"})
            except Exception:
                pass

        # Inherit transaction risk signals as fraud flags
        for sig in info["transaction_risk"].get("risk_signals", []):
            if sig["severity"] in ["HIGH", "MEDIUM"]:
                flags.append({"severity": sig["severity"], "message": f"{sig['signal']}: {sig['detail']}"})

        info["fraud_flags"] = flags
        info["risk_level"]  = (
            "HIGH"   if any(f["severity"] == "HIGH"   for f in flags) else
            "MEDIUM" if any(f["severity"] == "MEDIUM" for f in flags) else
            "LOW"
        )

        # ── Prevention actions — tells the app what to block ───────────────────
        prevention_actions = []
        if info["risk_level"] == "HIGH":
            prevention_actions.append("BLOCK_PAYMENT")
        elif info["risk_level"] == "MEDIUM":
            prevention_actions.append("WARN_BEFORE_PAYMENT")
        if not bool(mc) and amount:
            prevention_actions.append("VERIFY_RECIPIENT")
        if info.get("is_mobile_linked"):
            prevention_actions.append("VERIFY_MOBILE_OWNER")
        info["prevention_actions"] = prevention_actions

    except Exception as e:
        info["fraud_flags"] = [{"severity": "MEDIUM", "message": f"Parse error: {str(e)}"}]

    return info


# ── Main entry point ───────────────────────────────────────────────────────────
def analyze_non_url_qr(qr_type: str, data: str) -> dict:
    q_type = (qr_type or "").upper()
    result = {
        "qr_type":         qr_type,
        "reputation":      "SAFE",
        "confidence":      0.1,
        "reason":          "No threat detected",
        "sandbox_required": False,
        "parsed_data":     {},
    }

    d = data.lower()

    # ── UPI ──────────────────────────────────────────────────────────────────
    if q_type == "UPI":
        upi_info = parse_upi(data)
        result["parsed_data"]  = upi_info
        result["upi_analysis"] = upi_info
        result["is_upi"]       = True
        result["prevention_actions"] = upi_info.get("prevention_actions", [])
        risk = upi_info["risk_level"]
        if risk == "HIGH":
            result.update({"reputation": "DANGEROUS", "confidence": 0.85,
                           "reason": "High-risk UPI QR — suspicious signals detected",
                           "prevention_action": "BLOCK_PAYMENT"})
        elif risk == "MEDIUM":
            result.update({"reputation": "SUSPICIOUS", "confidence": 0.65,
                           "reason": "Suspicious UPI QR — verify before paying",
                           "prevention_action": "WARN_BEFORE_PAYMENT"})
        else:
            result.update({"reputation": "SAFE", "confidence": 0.1,
                           "reason": "UPI QR appears legitimate",
                           "prevention_action": "ALLOW"})

    # ── WiFi ─────────────────────────────────────────────────────────────────
    elif q_type in ["WIFI", "WI-FI"]:
        ssid_m = re.search(r"S:([^;]+)", data)
        auth_m = re.search(r"T:([^;]+)", data)
        ssid   = ssid_m.group(1) if ssid_m else "Unknown"
        auth   = auth_m.group(1).upper() if auth_m else "NONE"
        result["parsed_data"] = {"ssid": ssid, "security": auth, "is_hidden": "H:true" in d}
        if auth in ["NOPASS", "NONE", ""]:
            result.update({"reputation": "DANGEROUS", "confidence": 0.9,
                           "reason": "Open WiFi — no password protection", "sandbox_required": True})
        elif any(k in ssid.lower() for k in ["free", "public", "guest"]):
            result.update({"reputation": "SUSPICIOUS", "confidence": 0.6,
                           "reason": "Public/guest WiFi network"})

    # ── SMS ───────────────────────────────────────────────────────────────────
    elif q_type == "SMS":
        phone_m = re.search(r"sms:([+\d]+)", d)
        body_m  = re.search(r"body=(.+)", d)
        result["parsed_data"] = {
            "phone":   phone_m.group(1) if phone_m else "",
            "message": body_m.group(1).replace("+", " ") if body_m else data,
        }
        if any(k in d for k in ["otp", "bank", "prize", "win", "lottery", "reward"]):
            result.update({"reputation": "SUSPICIOUS", "confidence": 0.75,
                           "reason": "Suspicious keywords in SMS", "sandbox_required": True})

    # ── Email ─────────────────────────────────────────────────────────────────
    elif q_type == "EMAIL":
        to_m  = re.search(r"mailto:([^\?]+)", d)
        sub_m = re.search(r"subject=([^&]+)", d)
        bdy_m = re.search(r"body=([^&]+)", d)
        result["parsed_data"] = {
            "to":      to_m.group(1)  if to_m  else "",
            "subject": sub_m.group(1).replace("+", " ") if sub_m else "",
            "body":    bdy_m.group(1).replace("+", " ") if bdy_m else "",
        }
        combined = ((sub_m.group(1) if sub_m else "") + (bdy_m.group(1) if bdy_m else "")).lower()
        if any(k in combined for k in ["otp", "pin", "password", "bank", "prize", "lottery"]):
            result.update({"reputation": "SUSPICIOUS", "confidence": 0.75,
                           "reason": "Suspicious keywords in email QR", "sandbox_required": True})

    # ── Contact (vCard) ───────────────────────────────────────────────────────
    elif q_type in ["CONTACT", "VCARD"]:
        name_m  = re.search(r"FN:(.+)",        data)
        phone_m = re.search(r"TEL[^:]*:([+\d\s\-]+)", data)
        email_m = re.search(r"EMAIL[^:]*:([^\r\n]+)",  data)
        org_m   = re.search(r"ORG:(.+)",       data)
        result["parsed_data"] = {
            "name":  name_m.group(1).strip()  if name_m  else "",
            "phone": phone_m.group(1).strip() if phone_m else "",
            "email": email_m.group(1).strip() if email_m else "",
            "org":   org_m.group(1).strip()   if org_m   else "",
        }

    # ── App ───────────────────────────────────────────────────────────────────
    elif q_type == "APP":
        result["parsed_data"] = {"url": data}
        if "market://" not in d and "play.google.com/store" not in d:
            result.update({"reputation": "DANGEROUS", "confidence": 0.85,
                           "reason": "Non Play Store app installation", "sandbox_required": True})

    # ── Phone ─────────────────────────────────────────────────────────────────
    elif qr_type == "PHONE":
        result["parsed_data"] = {"phone": re.sub(r"[^+\d]", "", data.replace("tel:", ""))}

    # ── Geo ───────────────────────────────────────────────────────────────────
    elif qr_type == "GEO":
        coord_m = re.search(r"geo:([+-]?\d+\.?\d*),([+-]?\d+\.?\d*)", d)
        lat = coord_m.group(1) if coord_m else ""
        lon = coord_m.group(2) if coord_m else ""
        maps_link = f"https://maps.google.com/?q={lat},{lon}" if lat and lon else ""
        result["parsed_data"] = {"latitude": lat, "longitude": lon,
                                 "maps_link": maps_link, "raw": data}

    # ── Text ─────────────────────────────────────────────────────────────────
    elif qr_type == "TEXT":
        result["parsed_data"] = {"text": data}
        if len(data) > 60:
            result.update({"reputation": "SUSPICIOUS", "confidence": 0.65,
                           "reason": "Long encoded text payload"})

    return result
