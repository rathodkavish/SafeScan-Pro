"""
backend/utils/feature_extractor.py
Extracts 30 URL features matching the columns in phishing_dataset.csv.
Order: has_ip, url_length, num_dots, num_hyphens, num_underscores,
       num_slashes, num_at, num_question, num_equals, num_ampersand,
       has_https, has_http, subdomain_depth, has_phish_word, domain_length,
       path_length, query_length, num_digits_url, suspicious_tld, double_slash,
       hex_chars, num_percent, entropy, num_fragments, has_brand_name,
       tld_length, num_special, ratio_digits, ratio_letters, has_port
"""

import re
import math
from urllib.parse import urlparse
import socket


# ── Helper: check if string is a raw IP address ──────────────────────────────
def _is_ip_address(domain):
    try:
        socket.inet_aton(domain.split(":")[0])   # strip port if any
        return True
    except Exception:
        return False


# ── Helper: Shannon entropy of a string ──────────────────────────────────────
def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ── Brand names commonly impersonated in phishing ────────────────────────────
_BRANDS = [
    "paypal", "apple", "google", "facebook", "microsoft", "amazon",
    "netflix", "instagram", "linkedin", "twitter", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hdfc", "icici", "sbi",
    "flipkart", "paytm", "phonepe", "whatsapp", "telegram",
]

# ── Suspicious TLDs ──────────────────────────────────────────────────────────
_SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
                    ".buzz", ".club", ".work", ".info", ".ru", ".cn"]


# ═══════════════════════════════════════════════════════════════════════════════
# Main feature extraction — returns dict with 30 named features
# ═══════════════════════════════════════════════════════════════════════════════
def extract_url_features(url):
    features = {}

    try:
        # Ensure scheme for urlparse
        full_url = url if url.startswith(("http://", "https://")) else "http://" + url
        parsed = urlparse(full_url)
        domain = parsed.netloc or ""
        path   = parsed.path or ""
        query  = parsed.query or ""
        frag   = parsed.fragment or ""

        # Strip port from domain for analysis
        domain_no_port = domain.split(":")[0] if ":" in domain else domain
        tld = ""
        if "." in domain_no_port:
            tld = "." + domain_no_port.rsplit(".", 1)[-1]

        url_lower = url.lower()
        total_len = len(url) or 1  # avoid div-by-zero

        # ── 30 features in dataset column order ───────────────────────────────

        # 1. has_ip — is the domain a raw IP address?
        features["has_ip"] = 1 if _is_ip_address(domain_no_port) else 0

        # 2. url_length
        features["url_length"] = len(url)

        # 3. num_dots — in full URL
        features["num_dots"] = url.count(".")

        # 4. num_hyphens
        features["num_hyphens"] = url.count("-")

        # 5. num_underscores
        features["num_underscores"] = url.count("_")

        # 6. num_slashes
        features["num_slashes"] = url.count("/")

        # 7. num_at — count of '@'
        features["num_at"] = url.count("@")

        # 8. num_question — count of '?'
        features["num_question"] = url.count("?")

        # 9. num_equals — count of '='
        features["num_equals"] = url.count("=")

        # 10. num_ampersand — count of '&'
        features["num_ampersand"] = url.count("&")

        # 11. has_https
        features["has_https"] = 1 if url_lower.startswith("https://") else 0

        # 12. has_http (non-secure)
        features["has_http"] = 1 if url_lower.startswith("http://") else 0

        # 13. subdomain_depth
        parts = domain_no_port.split(".")
        features["subdomain_depth"] = max(len(parts) - 2, 0)

        # 14. has_phish_word — phishing keywords present?
        phish_words = ["login", "verify", "account", "secure", "update",
                       "confirm", "bank", "paypal", "signin", "password"]
        features["has_phish_word"] = 1 if any(w in url_lower for w in phish_words) else 0

        # 15. domain_length
        features["domain_length"] = len(domain_no_port)

        # 16. path_length
        features["path_length"] = len(path)

        # 17. query_length
        features["query_length"] = len(query)

        # 18. num_digits_url — total digits in URL
        features["num_digits_url"] = sum(c.isdigit() for c in url)

        # 19. suspicious_tld
        features["suspicious_tld"] = 1 if any(domain_no_port.lower().endswith(t)
                                               for t in _SUSPICIOUS_TLDS) else 0

        # 20. double_slash — '//' in path (after scheme)
        features["double_slash"] = 1 if "//" in path else 0

        # 21. hex_chars — count of hex-encoded chars (%XX patterns)
        features["hex_chars"] = len(re.findall(r"%[0-9a-fA-F]{2}", url))

        # 22. num_percent — count of '%'
        features["num_percent"] = url.count("%")

        # 23. entropy — Shannon entropy of URL string
        features["entropy"] = round(_shannon_entropy(url), 4)

        # 24. num_fragments — count of '#'
        features["num_fragments"] = url.count("#")

        # 25. has_brand_name — popular brand name in URL?
        features["has_brand_name"] = 1 if any(b in url_lower for b in _BRANDS) else 0

        # 26. tld_length
        features["tld_length"] = len(tld)

        # 27. num_special — non-alphanumeric, non-slash chars in URL
        features["num_special"] = len(re.findall(r"[^a-zA-Z0-9/.]", url))

        # 28. ratio_digits — digit ratio in URL
        features["ratio_digits"] = round(sum(c.isdigit() for c in url) / total_len, 4)

        # 29. ratio_letters — letter ratio in URL
        features["ratio_letters"] = round(sum(c.isalpha() for c in url) / total_len, 4)

        # 30. has_port — explicit port in URL?
        features["has_port"] = 1 if parsed.port else 0

    except Exception as e:
        print(f"Feature extraction error: {e}")
        # Return zeros for all 30 features
        for name in FEATURE_ORDER:
            features[name] = 0

    return features


# ═══════════════════════════════════════════════════════════════════════════════
# Feature order — MUST match the column order in phishing_dataset.csv
# ═══════════════════════════════════════════════════════════════════════════════
FEATURE_ORDER = [
    "has_ip", "url_length", "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_at", "num_question", "num_equals", "num_ampersand",
    "has_https", "has_http", "subdomain_depth", "has_phish_word",
    "domain_length", "path_length", "query_length", "num_digits_url",
    "suspicious_tld", "double_slash", "hex_chars", "num_percent",
    "entropy", "num_fragments", "has_brand_name", "tld_length",
    "num_special", "ratio_digits", "ratio_letters", "has_port",
]


def get_feature_vector(url):
    """Return a list of 30 numeric features in dataset column order."""
    features = extract_url_features(url)
    return [features.get(f, 0) for f in FEATURE_ORDER]
