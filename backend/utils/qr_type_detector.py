def detect_qr_type(data: str):
    """
    Detect QR code type. Matches the camera's client-side detectQRType logic
    so gallery uploads and camera scans are handled identically.
    """
    d = data.lower().strip()

    # URL (web links)
    if d.startswith("http://") or d.startswith("https://"):
        return "URL"

    # WiFi network
    if d.startswith("wifi:"):
        return "WIFI"

    # UPI payment — explicit prefix
    if d.startswith("upi://"):
        return "UPI"

    # SMS
    if d.startswith("smsto:") or d.startswith("sms:"):
        return "SMS"

    # Email
    if d.startswith("mailto:"):
        return "EMAIL"

    # Phone number
    if d.startswith("tel:"):
        return "PHONE"

    # Geographic location
    if d.startswith("geo:"):
        return "GEO"

    # Contact card (vCard)
    if d.startswith("begin:vcard"):
        return "CONTACT"

    # App install link
    if d.startswith("market://") or d.startswith("intent://") or "play.google.com/store" in d:
        return "APP"

    # UPI fallback — many real-world UPI QRs omit the upi:// prefix
    # Detect by presence of pa= (payee address) containing @ sign
    if "pa=" in d and "@" in d:
        return "UPI"

    return "TEXT"
