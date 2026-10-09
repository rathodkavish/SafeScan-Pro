"""Quick test: generate a SafeScan Pro PDF report and save it."""
import sys, os
sys.path.insert(0, ".")
os.environ["PYTHONUTF8"] = "1"

from utils.pdf_report import generate_report

# Simulate a dangerous UPI scan result
data = {
    "verdict": "DANGEROUS",
    "qr_data": "upi://pay?pa=5402109076@paytm&pn=Paytm+Cashback+Official&am=49999&cu=INR",
    "qr_type": "UPI",
    "risk_score": 83.8,
    "time": "2026-05-29T12:30:00",
    "score_breakdown": [
        {"signal": "Fraud Signal Analysis", "points": 40.0, "max": 40, "status": "THREAT",
         "detail": "4 fraud signal(s): Impersonation, large amount"},
        {"signal": "Transaction Risk", "points": 8.8, "max": 25, "status": "WARN",
         "detail": "Rs.49,999 on personal QR"},
        {"signal": "Identity Verification", "points": 20.0, "max": 20, "status": "THREAT",
         "detail": "Impersonation: Paytm Cashback Official"},
        {"signal": "QR Category Risk", "points": 15.0, "max": 15, "status": "THREAT",
         "detail": "Personal QR requesting large payment"},
    ],
    "upi_analysis": {
        "upi_id": "5402109076@paytm",
        "payee_name": "Paytm Cashback Official",
        "platform": "Paytm",
        "is_merchant_qr": False,
        "amount": "49999",
        "currency": "INR",
        "risk_level": "HIGH",
        "bank_name": "Paytm Payments Bank",
        "bank_type": "Payments Bank",
        "bank_headquarters": "Noida, UP",
        "bank_customer_care": "1800-120-4210",
        "bank_regulator": "RBI",
        "phone_number": "5402109076",
        "phone_formatted": "+91 54021 09076",
        "phone_carrier": "Unknown",
        "is_mobile_linked": True,
        "fraud_flags": [
            {"severity": "HIGH", "message": "Possible Financial bait impersonation in payee: 'Paytm Cashback Official'"},
            {"severity": "HIGH", "message": "Large pre-filled amount: Rs.49,999 - verify recipient"},
            {"severity": "MEDIUM", "message": "Personal QR with large pre-set amount is suspicious"},
            {"severity": "MEDIUM", "message": "Large amount Rs.49,999 on personal QR - verify recipient"},
        ],
        "transaction_risk": {
            "transaction_risk_score": 65,
            "transaction_risk_level": "HIGH",
            "amount_inr": "49999",
            "is_merchant_transaction": False,
        },
        "device_fingerprint": {
            "platform_hint": "Android",
            "os_hint": "Android 12+",
            "encoding_style": "Standard UPI",
            "qr_structure_hash": "a1b2c3d4e5",
        },
    },
    "forensic_evidence": {
        "evidence_id": "EVD-2026-0529-UPI-83A",
        "timestamp": "2026-05-29T12:30:00Z",
        "content_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924",
    },
    "blocked": True,
}

buf = generate_report(data)
out = os.path.join("reports", "test_safescan_report.pdf")
os.makedirs("reports", exist_ok=True)
with open(out, "wb") as f:
    f.write(buf.getvalue())
print(f"PDF generated: {out} ({os.path.getsize(out)} bytes)")
