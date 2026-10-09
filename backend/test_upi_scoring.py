"""
Test the non-URL scoring for the exact UPI QR code from the screenshot.
Payee: "Paytm Cashback Official", Amount: 49999, Personal QR, Platform: Paytm
"""
import sys, os
sys.path.insert(0, ".")
os.environ["PYTHONUTF8"] = "1"

from app import calculate_non_url_score
from utils.non_url_qr_analyzer import analyze_non_url_qr

def print_result(title, result):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    print(f"  Risk Score : {result['score']}%")
    verdict = "SAFE" if result["score"] < 40 else "SUSPICIOUS" if result["score"] < 70 else "DANGEROUS"
    print(f"  Verdict    : {verdict}")
    print(f"  Breakdown  :")
    for b in result["breakdown"]:
        icon = {"THREAT": "RED", "SAFE": "GRN", "WARN": "YLW", "SKIP": "---"}.get(b["status"], "---")
        print(f"    [{icon}] {b['signal']:30s} {b['points']:+6.1f} / {b['max']:3d}  [{b['status']}]  {b['detail']}")
    print()

# ── Test 1: The EXACT QR from the screenshot ──────────────────────────
# "Paytm Cashback Official" - Personal QR - Rs.49999 - Paytm
qr_data_1 = "upi://pay?pa=5402109076@paytm&pn=Paytm+Cashback+Official&am=49999&cu=INR"
print(f"QR Data: {qr_data_1}")
analysis_1 = analyze_non_url_qr("UPI", qr_data_1)
print(f"Fraud Flags: {len(analysis_1.get('parsed_data', {}).get('fraud_flags', []))}")
for f in analysis_1.get("parsed_data", {}).get("fraud_flags", []):
    print(f"  [{f['severity']}] {f['message']}")
result_1 = calculate_non_url_score(analysis_1, "UPI")
print_result("SCENARIO 1: Paytm Cashback Official - Rs.49999 (DANGEROUS UPI)", result_1)

# ── Test 2: Safe merchant QR ──────────────────────────────────────────
qr_data_2 = "upi://pay?pa=shop@okicici&pn=ABC+Store&mc=5411&am=250&cu=INR"
print(f"QR Data: {qr_data_2}")
analysis_2 = analyze_non_url_qr("UPI", qr_data_2)
result_2 = calculate_non_url_score(analysis_2, "UPI")
print_result("SCENARIO 2: Merchant QR - ABC Store Rs.250 (SAFE)", result_2)

# ── Test 3: Suspicious personal QR with moderate amount ───────────────
qr_data_3 = "upi://pay?pa=9876543210@ybl&pn=Quick+Refund&am=7500&cu=INR"
print(f"QR Data: {qr_data_3}")
analysis_3 = analyze_non_url_qr("UPI", qr_data_3)
result_3 = calculate_non_url_score(analysis_3, "UPI")
print_result("SCENARIO 3: 'Quick Refund' personal QR Rs.7500 (SUSPICIOUS)", result_3)

# ── Test 4: Open WiFi QR ─────────────────────────────────────────────
analysis_4 = analyze_non_url_qr("WIFI", "WIFI:S:FreeAirportWifi;T:nopass;P:;H:false;;")
result_4 = calculate_non_url_score(analysis_4, "WIFI")
print_result("SCENARIO 4: Open WiFi - no password (DANGEROUS)", result_4)

print("="*70)
print("  ALL TESTS COMPLETE")
print("="*70)
