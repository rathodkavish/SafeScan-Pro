#!/usr/bin/env python3
import re

with open("/home/ubuntu/SafeScan-Pro/backend/app.py", "r") as f:
    src = f.read()

# 1. Imports
src = src.replace(
    "from utils.sandbox_client import analyze_in_sandbox",
    "from utils.sandbox_client import analyze_in_sandbox\nfrom utils.ssl_inspector import inspect_ssl\nfrom utils.redirect_tracker import track_redirects\nfrom utils.homograph_detector import detect_homograph_typosquatting",
    1
)

# 2. calculate_score signature
src = src.replace(
    "def calculate_score(ml, vt, gsb, domain):",
    "def calculate_score(ml, vt, gsb, domain, ssl=None, redirects=None, homograph=None):",
    1
)

# 3. calculate_score body — add before final return
src = src.replace(
    "    return min(score, 100)",
    """    if ssl and isinstance(ssl, dict):
        score += ssl.get("ssl_risk_score", 0) * 0.15
    if redirects and isinstance(redirects, dict):
        score += redirects.get("redirect_risk_score", 0) * 0.10
    if homograph and isinstance(homograph, dict):
        score += homograph.get("homograph_risk_score", 0) * 0.20
    return min(score, 100)""",
    1
)

# 4. build_result signature
src = src.replace(
    'def build_result(url, ml, vt, gsb, domain, risk, sandbox_required, qr_type="URL", sandbox_report=None):',
    'def build_result(url, ml, vt, gsb, domain, risk, sandbox_required, qr_type="URL", sandbox_report=None, ssl=None, redirects=None, homograph=None):',
    1
)

# 5. build_result analysis dict
src = src.replace(
    '"domain": domain\n        },',
    '"domain": domain,\n            "ssl": ssl,\n            "redirects": redirects,\n            "homograph": homograph,\n        },',
    1
)

# 6. scan_url — add new checks
src = src.replace(
    '    risk = calculate_score(ml, vt, gsb, domain)\n\n    result = build_result(\n        url, ml, vt, gsb, domain,\n        risk, sandbox_required, "URL", sandbox_report\n    )\n\n    save_history({"type": "url", "data": result})',
    '    ssl       = inspect_ssl(url)\n    redirects = track_redirects(url)\n    homograph = detect_homograph_typosquatting(url)\n\n    risk = calculate_score(ml, vt, gsb, domain, ssl, redirects, homograph)\n\n    result = build_result(\n        url, ml, vt, gsb, domain,\n        risk, sandbox_required, "URL", sandbox_report,\n        ssl, redirects, homograph\n    )\n\n    save_history({"type": "url", "data": result})',
    1
)

# 7. scan_qr URL branch
src = src.replace(
    '        risk = calculate_score(ml, vt, gsb, domain)\n\n        result = build_result(\n            qr_data, ml, vt, gsb, domain,\n            risk, sandbox_required, "URL", sandbox_report\n        )\n        result["qr_data"] = qr_data',
    '        ssl       = inspect_ssl(qr_data)\n        redirects = track_redirects(qr_data)\n        homograph = detect_homograph_typosquatting(qr_data)\n\n        risk = calculate_score(ml, vt, gsb, domain, ssl, redirects, homograph)\n\n        result = build_result(\n            qr_data, ml, vt, gsb, domain,\n            risk, sandbox_required, "URL", sandbox_report,\n            ssl, redirects, homograph\n        )\n        result["qr_data"] = qr_data',
    1
)

# 8. scan_qr_data URL branch
src = src.replace(
    '        risk   = calculate_score(ml, vt, gsb, domain)\n        result = build_result(qr_data, ml, vt, gsb, domain, risk, sandbox_required, "URL", sandbox_report)\n        result["qr_data"] = qr_data',
    '        ssl       = inspect_ssl(qr_data)\n        redirects = track_redirects(qr_data)\n        homograph = detect_homograph_typosquatting(qr_data)\n\n        risk   = calculate_score(ml, vt, gsb, domain, ssl, redirects, homograph)\n        result = build_result(qr_data, ml, vt, gsb, domain, risk, sandbox_required, "URL", sandbox_report, ssl, redirects, homograph)\n        result["qr_data"] = qr_data',
    1
)

with open("/home/ubuntu/SafeScan-Pro/backend/app.py", "w") as f:
    f.write(src)

print("Patched. Verifying...")
checks = [
    ("ssl import",      "from utils.ssl_inspector import inspect_ssl"),
    ("redirect import", "from utils.redirect_tracker import track_redirects"),
    ("homograph import","from utils.homograph_detector import detect_homograph_typosquatting"),
    ("ssl in score",    'ssl.get("ssl_risk_score"'),
    ("ssl in analysis", '"ssl": ssl'),
    ("ssl in scan_url", "ssl       = inspect_ssl(url)"),
]
for name, text in checks:
    print(f"  {'OK' if text in src else 'MISSING'}: {name}")
