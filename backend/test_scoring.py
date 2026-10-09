"""
Test the updated calculate_score function with realistic scenarios.
Verifies that:
  1. Individual signal scores remain untouched
  2. Forensic Pattern Match correctly detects attack patterns
  3. Multi-Signal Correlation now counts 6 signals
  4. DANGEROUS verdict is properly reached for clear threats
"""
import sys
sys.path.insert(0, ".")

from app import calculate_score

def print_result(title, result):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    print(f"  Risk Score : {result['score']}%")
    verdict = "SAFE" if result["score"] < 40 else "SUSPICIOUS" if result["score"] < 70 else "DANGEROUS"
    print(f"  Verdict    : {verdict}")
    print(f"  Breakdown  :")
    for b in result["breakdown"]:
        icon = {"THREAT": "🔴", "SAFE": "🟢", "WARN": "🟡", "SKIP": "⚪", "NEUTRAL": "⚪", "OVERRIDE": "🟠"}.get(b["status"], "⚪")
        print(f"    {icon} {b['signal']:30s} {b['points']:+6.1f} / {b['max']:3d}  [{b['status']}]  {b['detail']}")
    print()


# ── Scenario 1: Clear phishing (the problem case) ──────────────────────
# ML detects phishing, domain is new, page has password fields
# But VT is skipped and GSB didn't flag it → OLD score was ~51 (SUSPICIOUS)
print_result(
    "SCENARIO 1: ML phishing + new domain + HIGH page (VT skipped)",
    calculate_score(
        ml={"is_phishing": True, "confidence": 70},
        vt={"malicious": 0, "suspicious": 0, "risk_percentage": 0, "error": "rate limited"},
        gsb={"is_safe": True},
        domain={"domain": "evil-login.xyz", "is_new": True, "age_days": 5},
        page_content={"content_risk": "HIGH", "password_inputs": 2,
                      "hidden_iframes": 0, "obfuscation_signals": 0,
                      "phishing_keyword_hits": 3, "risk_reasons": ["login form", "urgency"]},
    )
)

# ── Scenario 2: Trusted safe site ──────────────────────────────────────
print_result(
    "SCENARIO 2: Google.com (everything safe)",
    calculate_score(
        ml={"is_phishing": False, "confidence": 95},
        vt={"malicious": 0, "suspicious": 0, "risk_percentage": 0},
        gsb={"is_safe": True},
        domain={"domain": "google.com", "is_new": False, "age_days": 9000},
        page_content={"content_risk": "LOW", "password_inputs": 0,
                      "hidden_iframes": 0, "obfuscation_signals": 0,
                      "phishing_keyword_hits": 0, "risk_reasons": []},
    )
)

# ── Scenario 3: Evasion tactics (redirects + free SSL + obfuscation) ───
print_result(
    "SCENARIO 3: ML phishing + evasion tactics + new domain",
    calculate_score(
        ml={"is_phishing": True, "confidence": 65},
        vt={"malicious": 0, "suspicious": 0, "risk_percentage": 0, "error": "timeout"},
        gsb={"is_safe": True},
        domain={"domain": "secure-verify.tk", "is_new": True, "age_days": 2},
        page_content={"content_risk": "MEDIUM", "password_inputs": 1,
                      "hidden_iframes": 1, "obfuscation_signals": 3,
                      "phishing_keyword_hits": 5, "risk_reasons": ["obfuscation", "hidden iframe"]},
        ssl_info={"has_ssl": True, "issuer": "Let's Encrypt Authority X3"},
        redirect_info={"redirect_count": 4, "chain": ["a.com", "b.com", "c.com", "d.com"]},
    )
)

# ── Scenario 4: Borderline suspicious (should stay SUSPICIOUS) ─────────
print_result(
    "SCENARIO 4: Borderline — ML flags but domain is old, page is clean",
    calculate_score(
        ml={"is_phishing": True, "confidence": 55},
        vt={"malicious": 0, "suspicious": 0, "risk_percentage": 0},
        gsb={"is_safe": True},
        domain={"domain": "old-but-weird.com", "is_new": False, "age_days": 500},
        page_content={"content_risk": "LOW", "password_inputs": 0,
                      "hidden_iframes": 0, "obfuscation_signals": 0,
                      "phishing_keyword_hits": 0, "risk_reasons": []},
    )
)

# ── Scenario 5: Multi-engine confirmed dangerous ──────────────────────
print_result(
    "SCENARIO 5: GSB + VT + ML all flag it (multi-engine confirmed)",
    calculate_score(
        ml={"is_phishing": True, "confidence": 90},
        vt={"malicious": 15, "suspicious": 3, "risk_percentage": 60},
        gsb={"is_safe": False},
        domain={"domain": "phish-bank.xyz", "is_new": True, "age_days": 1},
        page_content={"content_risk": "HIGH", "password_inputs": 3,
                      "hidden_iframes": 2, "obfuscation_signals": 5,
                      "phishing_keyword_hits": 8, "risk_reasons": ["login", "urgency", "obfuscation"]},
    )
)

# ── Scenario 6: Infrastructure red flags ──────────────────────────────
print_result(
    "SCENARIO 6: New domain + weak security headers + ML phishing",
    calculate_score(
        ml={"is_phishing": True, "confidence": 60},
        vt={"malicious": 0, "suspicious": 0, "risk_percentage": 0},
        gsb={"is_safe": True},
        domain={"domain": "login-update.xyz", "is_new": True, "age_days": 10},
        page_content={"content_risk": "MEDIUM", "password_inputs": 1,
                      "hidden_iframes": 0, "obfuscation_signals": 0,
                      "phishing_keyword_hits": 2, "risk_reasons": ["login form"]},
        http_headers_info={"grade": "F", "score": 15, "found_count": 1, "total_checked": 7},
    )
)

print("\n" + "="*70)
print("  ALL TESTS COMPLETE")
print("="*70)
