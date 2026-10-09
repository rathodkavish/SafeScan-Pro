## SafeScan-Pro Showcase

![SafeScan-Pro Dashboard, Mobile App, Reports and Architecture](images/safescan-showcase.png)

<div align="center">

<img src="Documentation/Malware Qr.png" width="80" height="80" alt="SafeScan Pro Logo"/>

# 🛡️ SafeScan-Pro
### QR Code & URL Phishing Detection System

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![React Native](https://img.shields.io/badge/React%20Native-Expo%2055-blue.svg)](https://expo.dev)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com)
[![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-99.83%25-brightgreen.svg)](#)

**Author:** Kavish Ratho  
**Institution:** National Forensic Sciences University (NFSU), MSc DFIS  
**Year:** 2026

---

</div>

## 📌 About This Project

SafeScan-Pro is an AI-powered **QR Code and URL phishing detection system** built as a Minor Project for MSc Digital Forensics & Information Security at NFSU.

It protects users from:
- 🔗 **Phishing URLs** embedded in QR codes
- 💸 **Fraudulent UPI payment** QR codes
- 📶 **Insecure WiFi** QR codes that auto-connect to dangerous networks
- 📧 **Email & SMS phishing** via QR
- 🧬 **Malware download** links inside QR codes

---

## 🏗️ Architecture

```
SafeScan-Pro/
├── backend/          # Flask API + ML Model + Threat Intelligence
│   ├── app.py        # Main Flask server (REST API)
│   ├── utils/        # Feature extractor, QR decoder, API integrations
│   ├── models/       # Trained ML classifier (99.83% accuracy)
│   └── webui/        # Built Expo web app (served by Flask)
│
├── mobile/           # React Native / Expo cross-platform app
│   ├── app/          # Screens: Camera, Gallery, URL, History, Settings
│   └── constants/    # API configuration
│
├── frontend/         # Standalone lightweight HTML web interface
└── Documentation/    # Research paper, diagrams, project report
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📷 **Live Camera Scanner** | Real-time QR code scanning via device camera |
| 🖼️ **Gallery Upload** | Pick any QR image from your phone/PC gallery |
| 🔗 **URL Scanner** | Manually enter and scan any URL |
| 🤖 **ML Phishing Model** | Trained scikit-learn classifier with **99.83% accuracy** |
| 🦠 **VirusTotal Integration** | Checks URL against 70+ antivirus engines |
| 🔒 **Google Safe Browsing** | Real-time phishing/malware database check |
| 🌐 **Domain Age Analysis** | Detects newly registered suspicious domains |
| 💳 **UPI Scam Detection** | Blocks fraudulent UPI payment QR codes |
| 📊 **Threat Database** | Persistent threat cache — repeat threats blocked instantly |
| 📄 **PDF Report Generator** | Forensic-grade downloadable PDF scan reports |
| 📜 **Scan History** | All past scans saved in MongoDB Atlas |

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/SafeScan-Pro.git
cd SafeScan-Pro
```

### 2. Set Up Backend
```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up your environment variables
copy .env.example .env
# Edit .env and add your MongoDB URI and API keys

# Start the Flask server
set PYTHONUTF8=1
python app.py
```
Backend runs at: `http://127.0.0.1:5000`

### 3. Access the Web Interface
Open your browser and go to:
```
http://localhost:5000/web
```

### 4. Run the Mobile App (Optional)
```bash
cd mobile
npm install
npx expo start
```
- Press `w` to open in browser
- Scan the QR in terminal with Expo Go app (SDK 55)

---

## 🔑 Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in:

| Variable | Where to Get It |
|----------|----------------|
| `MONGO_URI` | [MongoDB Atlas](https://cloud.mongodb.com) — free M0 cluster |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/join-us) — free API |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com) — free, 1000/day |
| `GOOGLE_SAFE_BROWSING_KEY` | [Google Cloud Console](https://console.cloud.google.com) |

---

## 🧪 Test QR Codes

The project includes **55 test QR codes** in `backend/test_qr_codes/`:

| File | Type | Expected Result |
|------|------|----------------|
| `11_safe_google.png` | Safe URL | ✅ SAFE |
| `12_safe_github.png` | Safe URL | ✅ SAFE |
| `14_upi_prize_scam.png` | UPI Scam | 🚨 DANGEROUS |
| `01_gsb_phishing.png` | Phishing URL | 🚨 DANGEROUS |
| `21_wifi_open_dangerous.png` | Open WiFi | ⚠️ SUSPICIOUS |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan-url` | Scan a URL for threats |
| POST | `/api/scan-qr` | Upload a QR image for analysis |
| POST | `/api/scan-qr-data` | Scan raw decoded QR string |
| GET | `/api/history` | Get scan history |
| GET | `/api/threat-stats` | Get threat database statistics |
| POST | `/api/download-report` | Generate PDF forensic report |

---

## 📸 Screenshots

> Web UI accessible at `http://localhost:5000/web` after starting the backend.

---

## ⚖️ License & Copyright

```
Copyright (C) 2026 Kavish Ratho, NFSU
SafeScan-Pro is licensed under GNU General Public License v3.0
```

**You CAN:**
- ✅ Use this project for learning and research
- ✅ Modify and improve the code
- ✅ Share your modified version

**You MUST:**
- 📌 Credit the original author: **Kavish Ratho**
- 📌 Keep any derivative work under GPL v3
- 📌 Include this copyright notice

**You CANNOT:**
- ❌ Remove author credit / copyright notices
- ❌ Claim you are the original author
- ❌ Use commercially without written permission
- ❌ Re-license under a different license

See [LICENSE](LICENSE) for full legal terms.

---

## 👨‍💻 Author

**Kavish Ratho**  
MSc Digital Forensics & Information Security  
National Forensic Sciences University (NFSU), 2026

---

<div align="center">
<sub>Built with ❤️ for cybersecurity research. If you use this project, please star ⭐ and credit the author.</sub>
</div>
