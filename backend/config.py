import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ---------------- Flask ----------------
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = True

    # ---------------- Database ----------------
    # ✅ FIX: Use same variable name as app.py
    MONGO_URI = os.getenv('MONGO_URI', '')

    # ---------------- Sandbox ----------------
    # MAIN URL used by backend to call sandbox VM
    SANDBOX_API_URL = os.getenv(
        'SANDBOX_API_URL',
        'http://192.168.159.131:9000'
    )

    # ---------------- Cloudinary ----------------
    CLOUDINARY_CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME', '')
    CLOUDINARY_API_KEY = os.getenv('CLOUDINARY_API_KEY', '')
    CLOUDINARY_API_SECRET = os.getenv('CLOUDINARY_API_SECRET', '')

    # ---------------- APIs ----------------
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY', '')
    WHOIS_API_KEY = os.getenv('WHOIS_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

    # ---------------- Uploads ----------------
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
