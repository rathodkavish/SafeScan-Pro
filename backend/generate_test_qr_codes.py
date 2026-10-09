"""
generate_test_qr_codes.py
─────────────────────────
Generates QR code images to test SafeScan-Pro's detection system.

Uses:
  - Google Safe Browsing's OFFICIAL test URLs (designed for testing)
  - Crafted UPI scam patterns (no real payment possible)
  - WiFi, SMS, and other malicious QR types

Run: python generate_test_qr_codes.py
Output: Creates QR images in 'test_qr_codes/' folder
"""

import os
import qrcode
from qrcode.constants import ERROR_CORRECT_H

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "test_qr_codes")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_qr(data: str, filename: str, label: str):
    """Generate a QR code image."""
    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_H, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    path = os.path.join(OUTPUT_DIR, filename)
    img.save(path)
    print(f"  ✅ {filename:45s} → {label}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# 1. URL-BASED — GOOGLE SAFE BROWSING OFFICIAL TEST URLS
#    These are Google's own test pages that trigger Safe Browsing alerts.
#    They are SAFE to scan — they exist specifically for testing security tools.
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === DANGEROUS URL QR CODES (should trigger DANGEROUS) ===")

# Phishing test page
make_qr(
    "http://testsafebrowsing.appspot.com/s/phishing.html",
    "01_gsb_phishing.png",
    "Google Safe Browsing — PHISHING test page"
)

# Malware test page
make_qr(
    "http://testsafebrowsing.appspot.com/s/malware.html",
    "02_gsb_malware.png",
    "Google Safe Browsing — MALWARE test page"
)

# Unwanted software test page
make_qr(
    "http://testsafebrowsing.appspot.com/s/unwanted.html",
    "03_gsb_unwanted.png",
    "Google Safe Browsing — UNWANTED SOFTWARE test page"
)

# Social engineering test page
make_qr(
    "http://testsafebrowsing.appspot.com/s/social_engineering.html",
    "04_gsb_social_engineering.png",
    "Google Safe Browsing — SOCIAL ENGINEERING test page"
)


# ══════════════════════════════════════════════════════════════════════════════
# 2. WICAR — Official malware test site for security testing
# ══════════════════════════════════════════════════════════════════════════════
make_qr(
    "https://www.wicar.org/test-malware.html",
    "05_wicar_malware_test.png",
    "WICAR.org — Official malware test page"
)

# EICAR test — standard antivirus test URL
make_qr(
    "https://secure.eicar.org/eicar.com",
    "06_eicar_test.png",
    "EICAR — Standard antivirus test file URL"
)


# ══════════════════════════════════════════════════════════════════════════════
# 3. SUSPICIOUS URL PATTERNS — common phishing tricks
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === SUSPICIOUS URL QR CODES (should trigger SUSPICIOUS) ===")

# URL with IP address instead of domain (phishing indicator)
make_qr(
    "http://93.184.216.34/login/verify-account.html",
    "07_ip_address_url.png",
    "IP address URL — no domain name (phishing trick)"
)

# Typosquatting - looks like Google but isn't
make_qr(
    "https://g00gle-security-alert.example.com/verify",
    "08_typosquat_google.png",
    "Typosquatting — fake Google security alert"
)

# URL shortener hiding the real destination
make_qr(
    "https://bit.ly/3xMaLiCi0us",
    "09_url_shortener.png",
    "URL shortener — hides real destination"
)

# Very long suspicious URL
make_qr(
    "https://secure-banking-login-verify-account-update-now.example.com/signin?redirect=true&token=abc123&urgent=true",
    "10_long_suspicious_url.png",
    "Long suspicious URL with urgency keywords"
)


# ══════════════════════════════════════════════════════════════════════════════
# 4. SAFE URL QR CODES — should pass as SAFE
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟢 === SAFE URL QR CODES (should show SAFE) ===")

make_qr("https://www.google.com", "11_safe_google.png", "Google.com — SAFE")
make_qr("https://www.github.com", "12_safe_github.png", "GitHub.com — SAFE")
make_qr("https://www.wikipedia.org", "13_safe_wikipedia.png", "Wikipedia — SAFE")


# ══════════════════════════════════════════════════════════════════════════════
# 5. UPI SCAM QR CODES — crafted to test UPI fraud detection
#    These are FAKE UPI IDs — no real payment can happen
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === UPI SCAM QR CODES (should trigger DANGEROUS) ===")

# Prize scam — mobile-linked, large amount, suspicious payee
make_qr(
    "upi://pay?pa=9876543210@ybl&pn=PRIZE+WINNER+LOTTERY&am=50000&tn=Claim+your+prize+send+OTP",
    "14_upi_prize_scam.png",
    "UPI SCAM — Fake prize/lottery, ₹50,000, asks for OTP"
)

# Bank impersonation scam — pretends to be SBI refund
make_qr(
    "upi://pay?pa=8765432109@paytm&pn=SBI+Refund+Department&am=25000&tn=Your+refund+is+pending+verify+now",
    "15_upi_sbi_impersonation.png",
    "UPI SCAM — SBI impersonation, fake refund ₹25,000"
)

# RBI impersonation
make_qr(
    "upi://pay?pa=7654321098@oksbi&pn=RBI+Cashback+Official&am=100000&tn=RBI+approved+cashback+claim+immediately",
    "16_upi_rbi_impersonation.png",
    "UPI SCAM — RBI impersonation, ₹1,00,000"
)

# Personal QR with large amount — no merchant code
make_qr(
    "upi://pay?pa=6543210987@ybl&pn=Quick+Money&am=99999&tn=Send+money+urgently+or+account+blocked",
    "17_upi_urgency_scam.png",
    "UPI SCAM — Urgency, personal QR, ₹99,999"
)

# HDFC impersonation scam
make_qr(
    "upi://pay?pa=9999888877@okhdfc&pn=HDFC+Support+Helpdesk&am=15000&tn=KYC+verification+mandatory",
    "18_upi_hdfc_impersonation.png",
    "UPI SCAM — HDFC impersonation, KYC fraud, ₹15,000"
)


# ══════════════════════════════════════════════════════════════════════════════
# 6. SAFE UPI QR CODES — legitimate patterns
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟢 === SAFE UPI QR CODES (should show SAFE) ===")

# Normal merchant QR (with merchant code)
make_qr(
    "upi://pay?pa=merchant@axisbank&pn=Chai+Point+Store&mc=5411&am=150&cu=INR",
    "19_upi_safe_merchant.png",
    "SAFE — Normal merchant QR with merchant code, ₹150"
)

# Personal QR without amount (just receiving ID)
make_qr(
    "upi://pay?pa=ramesh.kumar@paytm&pn=Ramesh+Kumar",
    "20_upi_safe_personal.png",
    "SAFE — Personal QR, no amount, no suspicious signals"
)


# ══════════════════════════════════════════════════════════════════════════════
# 7. WIFI QR CODES — open network (no password = dangerous)
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === WIFI QR CODES ===")

# Open WiFi — no encryption (dangerous)
make_qr(
    "WIFI:T:nopass;S:FREE_AIRPORT_WIFI;P:;;",
    "21_wifi_open_dangerous.png",
    "WIFI — Open network, no password (DANGEROUS)"
)

# WPA2 secured WiFi (safe)
make_qr(
    "WIFI:T:WPA2;S:HomeNetwork;P:MySecurePass123;;",
    "22_wifi_wpa2_safe.png",
    "WIFI — WPA2 encrypted, has password (SAFE)"
)

# Hidden SSID + open (suspicious)
make_qr(
    "WIFI:T:nopass;S:HiddenNetwork;H:true;P:;;",
    "23_wifi_hidden_open.png",
    "WIFI — Hidden SSID + No password (SUSPICIOUS)"
)


# ══════════════════════════════════════════════════════════════════════════════
# 8. SMS/PHONE QR CODES
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === SMS/PHONE QR CODES ===")

# SMS scam — premium number with OTP request
make_qr(
    "SMSTO:+911234567890:Your account will be blocked. Send OTP 456789 to verify immediately.",
    "24_sms_scam_otp.png",
    "SMS SCAM — Fake account block, asks for OTP"
)

# Safe phone number
make_qr(
    "tel:+911800123456",
    "25_phone_safe_tollfree.png",
    "PHONE — Toll-free number (SAFE)"
)


# ══════════════════════════════════════════════════════════════════════════════
# 9. SSRF ATTACK QR CODES — should be BLOCKED by url_safety.py
# ══════════════════════════════════════════════════════════════════════════════
print("\n🛡 === SSRF ATTACK QR CODES (should be BLOCKED by security guard) ===")

make_qr(
    "http://localhost:27017/admin",
    "26_ssrf_localhost.png",
    "SSRF — Tries to access localhost MongoDB"
)

make_qr(
    "http://192.168.1.1/admin",
    "27_ssrf_private_ip.png",
    "SSRF — Tries to access private network router"
)

make_qr(
    "http://169.254.169.254/latest/meta-data/",
    "28_ssrf_cloud_metadata.png",
    "SSRF — Tries to steal AWS/GCP cloud credentials"
)

make_qr(
    "file:///etc/passwd",
    "29_protocol_attack.png",
    "PROTOCOL ATTACK — Tries to read system files"
)


# ══════════════════════════════════════════════════════════════════════════════
# 10. VCARD / EMAIL QR CODES
# ══════════════════════════════════════════════════════════════════════════════
print("\n📧 === EMAIL / VCARD QR CODES ===")

make_qr(
    "MATMSG:TO:security-alert@fakebank.com;SUB:Urgent Account Verification;BODY:Click link to verify your account or it will be permanently locked;;",
    "30_email_phishing.png",
    "EMAIL — Phishing email with urgency"
)



# ══════════════════════════════════════════════════════════════════════════════
# 11. CRYPTO / FINANCIAL SCAM URLs
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === CRYPTO / FINANCIAL SCAM QR CODES ===")

make_qr(
    "https://free-bitcoin-claim.example.xyz/wallet?ref=URGENT&bonus=500BTC",
    "31_crypto_scam_btc.png",
    "CRYPTO SCAM — Fake Bitcoin giveaway"
)

make_qr(
    "https://metamask-verify-wallet.example.com/connect?seed=true",
    "32_crypto_wallet_phish.png",
    "CRYPTO SCAM — Fake MetaMask seed phrase phishing"
)

make_qr(
    "https://amazon-order-refund-verify.example.in/login?order=112-3456789&urgent=1",
    "33_ecommerce_refund_scam.png",
    "E-COMMERCE SCAM — Fake Amazon refund page"
)


# ══════════════════════════════════════════════════════════════════════════════
# 12. HOMOGRAPH / IDN ATTACKS — visually confusing domains
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === HOMOGRAPH / IDN ATTACK QR CODES ===")

make_qr(
    "https://xn--80ak6aa92e.com/login",
    "34_idn_homograph_apple.png",
    "IDN HOMOGRAPH — Punycode domain mimicking 'apple.com'"
)

make_qr(
    "https://paypa1-secure-update.example.com/signin",
    "35_typosquat_paypal.png",
    "TYPOSQUAT — paypa1 (letter l → digit 1) mimicking PayPal"
)


# ══════════════════════════════════════════════════════════════════════════════
# 13. REDIRECT CHAIN / OPEN REDIRECT ABUSE
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === REDIRECT / OBFUSCATION QR CODES ===")

make_qr(
    "https://www.google.com/url?q=http://evil-phishing-site.example.com/steal",
    "36_open_redirect_google.png",
    "OPEN REDIRECT — Abuses Google redirect to phishing site"
)

make_qr(
    "https://t.co/aB3cD4eF5g?amp=1&redirect=http://malware-download.example.net",
    "37_redirect_chain_twitter.png",
    "REDIRECT CHAIN — Twitter shortener to malware"
)


# ══════════════════════════════════════════════════════════════════════════════
# 14. DATA EXFILTRATION / ENCODED URL ATTACKS
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === DATA EXFILTRATION QR CODES ===")

make_qr(
    "https://attacker.example.com/collect?data=base64_encoded_credentials_here&src=qr_scan",
    "38_data_exfiltration.png",
    "DATA EXFIL — URL designed to steal scanned data"
)

make_qr(
    "javascript:alert(document.cookie)",
    "39_javascript_injection.png",
    "JAVASCRIPT INJECTION — Attempts cookie theft via JS"
)


# ══════════════════════════════════════════════════════════════════════════════
# 15. FAKE LOGIN PAGES — credential harvesting
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === FAKE LOGIN PAGE QR CODES ===")

make_qr(
    "https://secure-signin-microsoft365.example.org/office/login.php?session=expired",
    "40_fake_microsoft_login.png",
    "FAKE LOGIN — Microsoft 365 credential harvester"
)

make_qr(
    "https://netflix-billing-update.example.com/account/payment?status=suspended",
    "41_fake_netflix_billing.png",
    "FAKE LOGIN — Netflix billing scam, account suspended"
)


# ══════════════════════════════════════════════════════════════════════════════
# 16. VCARD PHISHING — social engineering via contact cards
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === VCARD / CONTACT QR CODES ===")

make_qr(
    "BEGIN:VCARD\nVERSION:3.0\nN:Support;Microsoft\nFN:Microsoft Support\n"
    "TEL;TYPE=CELL:+911234567890\nEMAIL:support@m1crosoft-help.example.com\n"
    "URL:https://m1crosoft-support.example.com/helpdesk\nEND:VCARD",
    "42_vcard_phishing_microsoft.png",
    "VCARD PHISHING — Fake Microsoft support contact"
)

make_qr(
    "BEGIN:VCARD\nVERSION:3.0\nN:Sharma;Rajesh\nFN:Rajesh Sharma\n"
    "TEL;TYPE=CELL:+919876543210\nEMAIL:rajesh@gmail.com\nEND:VCARD",
    "43_vcard_safe_personal.png",
    "VCARD SAFE — Normal personal contact card"
)


# ══════════════════════════════════════════════════════════════════════════════
# 17. CALENDAR EVENT — social engineering via fake events
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === CALENDAR EVENT QR CODES ===")

make_qr(
    "BEGIN:VEVENT\nSUMMARY:URGENT: Your Bank Account Verification Required\n"
    "DTSTART:20260520T100000Z\nDTEND:20260520T110000Z\n"
    "DESCRIPTION:Click here to verify: https://sbi-kyc-verify.example.com/urgent\n"
    "LOCATION:Online\nEND:VEVENT",
    "44_calendar_bank_scam.png",
    "CALENDAR SCAM — Fake bank verification event"
)


# ══════════════════════════════════════════════════════════════════════════════
# 18. MORE WIFI ATTACK VARIANTS
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟡 === MORE WIFI QR CODES ===")

# WEP (deprecated, easily cracked encryption)
make_qr(
    "WIFI:T:WEP;S:CoffeeShop_Free;P:12345;H:false;;",
    "45_wifi_wep_weak.png",
    "WIFI — WEP encryption (weak, easily cracked) SUSPICIOUS"
)

# Evil Twin — mimics a known network name
make_qr(
    "WIFI:T:nopass;S:Starbucks_WiFi_Free;P:;;",
    "46_wifi_evil_twin.png",
    "WIFI — Evil Twin attack, mimics Starbucks, open network"
)


# ══════════════════════════════════════════════════════════════════════════════
# 19. ADDITIONAL UPI SCAM VARIANTS
# ══════════════════════════════════════════════════════════════════════════════
print("\n🔴 === MORE UPI SCAM QR CODES ===")

# Paytm cashback scam
make_qr(
    "upi://pay?pa=5432109876@paytm&pn=Paytm+Cashback+Official&am=49999&tn=Cashback+credited+pay+processing+fee",
    "47_upi_paytm_cashback_scam.png",
    "UPI SCAM — Fake Paytm cashback, processing fee ₹49,999"
)

# Insurance scam
make_qr(
    "upi://pay?pa=8888777766@ybl&pn=LIC+Policy+Renewal&am=75000&tn=Policy+lapsed+renew+immediately+or+lose+coverage",
    "48_upi_insurance_scam.png",
    "UPI SCAM — Fake LIC policy renewal, ₹75,000"
)

# Investment scam
make_qr(
    "upi://pay?pa=7777666655@oksbi&pn=SIP+Investment+Returns&am=100000&tn=Guaranteed+500+percent+returns+invest+now",
    "49_upi_investment_scam.png",
    "UPI SCAM — Fake investment, guaranteed returns, ₹1,00,000"
)


# ══════════════════════════════════════════════════════════════════════════════
# 20. SAFE URLS — more legitimate websites for baseline
# ══════════════════════════════════════════════════════════════════════════════
print("\n🟢 === MORE SAFE URL QR CODES ===")

make_qr("https://www.stackoverflow.com", "50_safe_stackoverflow.png", "StackOverflow — SAFE")
make_qr("https://www.microsoft.com", "51_safe_microsoft.png", "Microsoft.com — SAFE")
make_qr("https://www.flipkart.com", "52_safe_flipkart.png", "Flipkart.com — SAFE")


# ══════════════════════════════════════════════════════════════════════════════
# 21. PROTOCOL ABUSE — more dangerous protocol QR codes
# ══════════════════════════════════════════════════════════════════════════════
print("\n🛡 === MORE PROTOCOL ABUSE QR CODES ===")

make_qr(
    "ftp://anonymous@suspicious-server.example.com/malware/payload.exe",
    "53_ftp_malware_download.png",
    "FTP — Anonymous access to download malware"
)

make_qr(
    "ssh://root@192.168.1.100:22",
    "54_ssh_private_network.png",
    "SSH — Attempts connection to private network"
)

make_qr(
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
    "55_data_uri_xss.png",
    "DATA URI — Base64-encoded XSS payload"
)


# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"✅ Generated {len(os.listdir(OUTPUT_DIR))} test QR codes in: {OUTPUT_DIR}")
print(f"{'='*60}")
print("""
HOW TO USE:
1. Start your backend:  cd backend && python app.py
2. Open the mobile app
3. Scan each QR code from this folder
4. Verify the verdict matches the expected result

EXPECTED RESULTS:
  01-06: DANGEROUS (Google Safe Browsing / malware test)
  07-10: SUSPICIOUS (phishing patterns)
  11-13: SAFE (legitimate websites)
  14-18: DANGEROUS (UPI scam patterns)
  19-20: SAFE (legitimate UPI)
  21:    DANGEROUS (open WiFi)
  22:    SAFE (encrypted WiFi)
  23:    SUSPICIOUS (hidden + open WiFi)
  24:    SUSPICIOUS (SMS scam)
  25:    SAFE (phone number)
  26-29: BLOCKED (SSRF attacks — url_safety.py)
  30:    SUSPICIOUS (phishing email)
  ─── NEW TEST CASES ───
  31-33: DANGEROUS (crypto / financial scams)
  34-35: SUSPICIOUS (homograph / typosquat attacks)
  36-37: SUSPICIOUS (redirect chain / open redirect abuse)
  38-39: DANGEROUS (data exfiltration / JS injection)
  40-41: DANGEROUS (fake login credential harvesters)
  42:    SUSPICIOUS (vCard phishing — fake support)
  43:    SAFE (vCard — normal personal contact)
  44:    SUSPICIOUS (calendar event social engineering)
  45:    SUSPICIOUS (WiFi WEP — weak encryption)
  46:    DANGEROUS (WiFi evil twin — open + mimics brand)
  47-49: DANGEROUS (UPI scams — cashback/insurance/investment)
  50-52: SAFE (legitimate websites)
  53-55: BLOCKED (protocol abuse — FTP/SSH/data URI)
""")
