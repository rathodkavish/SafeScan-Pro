"""SafeScan-Pro Comprehensive Test Suite"""
import sys, json, time
sys.path.insert(0, '.')

print('='*70)
print('  SAFESCAN-PRO COMPREHENSIVE TEST SUITE')
print('='*70)

# ── Test 1: Imports & Module Loading ──
print('\n[TEST 1] Module Loading...')
try:
    from app import calculate_score, build_result
    from utils.api_integrations import check_domain_age
    from utils.url_safety import safe_url_or_raise
    from utils.non_url_qr_analyzer import analyze_non_url_qr
    from utils.qr_type_detector import detect_qr_type
    print('  PASS: All modules loaded successfully')
except Exception as e:
    print(f'  FAIL: {e}')

passed = 0
failed = 0

def test(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  PASS: {name}')
    else:
        failed += 1
        print(f'  FAIL: {name} -- {detail}')

# ── Test 2: Score Breakdown Structure ──
print('\n[TEST 2] Score Breakdown Structure...')
ml = {'is_phishing': True, 'confidence': 92}
vt = {'risk_percentage': 0}
gsb = {'is_safe': False}
dom = {'is_new': True, 'age_days': 5}
r = calculate_score(ml, vt, gsb, dom)
test('Returns dict with score', 'score' in r, str(r.keys()))
test('Returns breakdown list', 'breakdown' in r and isinstance(r['breakdown'], list))
bd_len = len(r['breakdown'])
test(f'Breakdown has 4+ items (got {bd_len})', bd_len >= 4)
for b in r['breakdown']:
    has_keys = all(k in b for k in ['signal','points','max','status','detail'])
    test(f'  {b["signal"]} has all fields', has_keys)

# ── Test 3: Safe URL = Low Score ──
print('\n[TEST 3] Safe URL Scoring...')
ml_safe = {'is_phishing': False, 'confidence': 85}
vt_clean = {'risk_percentage': 0}
gsb_safe = {'is_safe': True}
dom_old = {'is_new': False, 'age_days': 5000}
r = calculate_score(ml_safe, vt_clean, gsb_safe, dom_old)
test(f'Safe URL score < 10 (got {r["score"]})', r['score'] < 10)

# ── Test 4: Phishing URL = High Score ──
print('\n[TEST 4] Phishing URL Scoring...')
ml_phish = {'is_phishing': True, 'confidence': 95}
gsb_bad = {'is_safe': False}
dom_new = {'is_new': True, 'age_days': 3}
r = calculate_score(ml_phish, vt_clean, gsb_bad, dom_new)
test(f'Phishing score >= 70 DANGEROUS (got {r["score"]})', r['score'] >= 70)

# ── Test 5: GSB alone triggers SUSPICIOUS ──
print('\n[TEST 5] GSB Override...')
r = calculate_score(ml_safe, vt_clean, gsb_bad, dom_old)
test(f'GSB alone score >= 40 (got {r["score"]})', r['score'] >= 40)

# ── Test 6: ML safe + no threats = truly SAFE ──
print('\n[TEST 6] No False Positives...')
r = calculate_score(ml_safe, vt_clean, gsb_safe, dom_old)
test(f'Clean URL score < 40 SAFE (got {r["score"]})', r['score'] < 40)

# ── Test 7: Domain Age - Unknown (.in domains) ──
print('\n[TEST 7] Domain Age - Unknown Handling...')
dom_unknown = {'is_new': 'unknown', 'age_days': None}
r = calculate_score(ml_safe, vt_clean, gsb_safe, dom_unknown)
has_warn = any(b['status'] == 'WARN' and 'Domain' in b['signal'] for b in r['breakdown'])
test('Unknown domain gets WARN status', has_warn)
dom_pts = [b['points'] for b in r['breakdown'] if 'Domain' in b['signal']][0]
test(f'Unknown domain adds cautious pts (got {dom_pts})', dom_pts in [6, 4.5] or dom_pts >= 4.0)

# ── Test 8: Domain Age - RDAP Fallback ──
print('\n[TEST 8] Domain Age RDAP Fallback...')
result = check_domain_age('https://luminaview.in')
test(f'luminaview.in age_days={result["age_days"]}', result['age_days'] is not None)
test(f'luminaview.in age verified (>0 days)', result.get('age_days') is not None and result.get('age_days') > 0)

# ── Test 9: Domain Age - Known Domains ──
print('\n[TEST 9] Domain Age - Known Domains...')
result = check_domain_age('https://www.google.com')
test(f'google.com age={result["age_days"]} days', result['age_days'] is not None and result['age_days'] > 10000)
test(f'google.com is_new=False', result['is_new'] == False)

# ── Test 10: SSRF Protection ──
print('\n[TEST 10] SSRF Protection...')
ssrf_tests = [
    ('http://localhost/admin', 'localhost'),
    ('http://127.0.0.1/secret', 'loopback'),
    ('http://192.168.1.1/router', 'private IP'),
    ('http://169.254.169.254/metadata', 'cloud metadata'),
    ('file:///etc/passwd', 'file protocol'),
    ('http://10.0.0.1/internal', 'private 10.x'),
]
for url, desc in ssrf_tests:
    try:
        safe_url_or_raise(url)
        test(f'Block {desc}', False, 'NOT BLOCKED!')
    except ValueError:
        test(f'Block {desc}', True)
    except Exception as e:
        test(f'Block {desc}', True)

# Allow safe URLs
safe_urls = ['https://www.google.com', 'https://github.com']
for url in safe_urls:
    try:
        safe_url_or_raise(url)
        test(f'Allow {url}', True)
    except Exception as e:
        test(f'Allow {url}', False, str(e))

# ── Test 11: QR Type Detection ──
print('\n[TEST 11] QR Type Detection...')
qr_tests = [
    ('https://www.google.com', 'URL'),
    ('http://evil.com/phish', 'URL'),
    ('upi://pay?pa=shop@upi&pn=Shop&am=100', 'UPI'),
    ('WIFI:T:WPA2;S:MyNetwork;P:pass123;;', 'WiFi'),
    ('smsto:+919876543210:Hello', 'SMS'),
    ('tel:+919876543210', 'Phone'),
    ('mailto:test@example.com', 'Email'),
    ('BEGIN:VCARD', 'vCard'),
]
for data, expected in qr_tests:
    result = detect_qr_type(data)
    matches = (result.upper() == expected.upper()) or (expected.upper() in ["VCARD", "CONTACT"] and result == "CONTACT")
    test(f'{expected} detection (got={result})', matches)

# ── Test 12: UPI Merchant QR (No False Positive) ──
print('\n[TEST 12] UPI Merchant QR - No False Positive...')
merchant_qr = 'upi://pay?pa=merchant@axisbank&pn=Tea%20Shop&mc=5812&am=150&cu=INR'
analysis = analyze_non_url_qr('UPI', merchant_qr)
verdict = analysis.get('reputation', '')
test(f'Merchant QR = SAFE (got {verdict})', verdict in ['SAFE', 'CLEAN'])

# ── Test 13: UPI Scam QR (Correctly Detected) ──
print('\n[TEST 13] UPI Scam QR Detection...')
scam_qr = 'upi://pay?pa=lottery2024@ybl&pn=PRIZE%20WINNER&am=9999&cu=INR&tn=Send%20OTP%20to%20claim%20prize'
analysis = analyze_non_url_qr('UPI', scam_qr)
verdict = analysis.get('reputation', '')
test(f'Scam QR != SAFE (got {verdict})', verdict != 'SAFE')

# ── Test 14: WiFi QR Analysis ──
print('\n[TEST 14] WiFi QR Analysis...')
wifi_open = 'WIFI:T:nopass;S:FreeAirportWiFi;;'
analysis = analyze_non_url_qr('WiFi', wifi_open)
verdict = analysis.get('reputation', '')
test(f'Open WiFi flagged (got {verdict})', verdict != 'SAFE')

wifi_secure = 'WIFI:T:WPA2;S:HomeNetwork;P:SecurePass123;;'
analysis = analyze_non_url_qr('WiFi', wifi_secure)
verdict = analysis.get('reputation', '')
test(f'Secure WiFi = SAFE (got {verdict})', verdict == 'SAFE')

# ── Test 15: Verdict Thresholds ──
print('\n[TEST 15] Verdict Thresholds...')
# Score 0 = SAFE
r = calculate_score(ml_safe, vt_clean, gsb_safe, dom_old)
verdict = 'SAFE' if r['score'] < 40 else 'SUSPICIOUS' if r['score'] < 70 else 'DANGEROUS'
test(f'Score {r["score"]} -> {verdict}', verdict == 'SAFE')

# Score with GSB only = SUSPICIOUS (40+)
r = calculate_score(ml_safe, vt_clean, gsb_bad, dom_old)
verdict = 'SAFE' if r['score'] < 40 else 'SUSPICIOUS' if r['score'] < 70 else 'DANGEROUS'
test(f'Score {r["score"]} -> {verdict}', verdict == 'SUSPICIOUS')

# Score with everything bad = DANGEROUS (70+)
vt_bad = {'risk_percentage': 60}
r = calculate_score(ml_phish, vt_bad, gsb_bad, dom_new)
verdict = 'SAFE' if r['score'] < 40 else 'SUSPICIOUS' if r['score'] < 70 else 'DANGEROUS'
test(f'Score {r["score"]} -> {verdict}', verdict == 'DANGEROUS')

# ── Test 16: Multi-Signal Correlation Bonus ──
print('\n[TEST 16] Multi-Signal Correlation...')
r = calculate_score(ml_phish, vt_clean, gsb_bad, dom_old)
has_corr = any('Correlation' in b['signal'] for b in r['breakdown'])
test('Correlation bonus present when ML+GSB agree', has_corr)

# ── Summary ──
print('\n' + '='*70)
status = 'ALL TESTS PASSED' if failed == 0 else f'{failed} TEST(S) FAILED'
print(f'  RESULTS: {passed} PASSED, {failed} FAILED out of {passed+failed} tests')
print(f'  STATUS:  {status}')
print('='*70)
