import requests
from config import Config

def analyze_in_sandbox(url):
    """
    Calls Sandbox VM and returns a fully normalized sandbox report.
    Adds runtime visibility and safe error handling.
    """

    # 🔍 DEBUG: confirm which sandbox URL is actually used
    print("🧪 CALLING SANDBOX AT:", Config.SANDBOX_API_URL)

    try:
        response = requests.post(
            Config.SANDBOX_API_URL + "/analyze",
            json={"url": url},
            timeout=90
        )

        # 🚨 Handle non-200 responses explicitly
        if response.status_code != 200:
            print("❌ SANDBOX HTTP ERROR:", response.status_code)
            print(response.text)
            return None

        data = response.json()

        # Sandbox always returns { sandbox_report: {...} }
        report = data.get("sandbox_report")
        if not isinstance(report, dict):
            print("❌ INVALID SANDBOX RESPONSE:", data)
            return None

        # ✅ FULL NORMALIZATION (frontend-safe)
        return {
            "malware_score": report.get("malware_score", 0),
            "js_executed": report.get("js_executed"),
            "downloads": report.get("downloads") or [],
            "redirects": report.get("redirects") or [],
            "dns_ips": report.get("dns_ips") or [],
            "connections": report.get("connections") or []
        }

    except requests.exceptions.Timeout:
        print("❌ SANDBOX ERROR: Timeout")
        return None

    except requests.exceptions.ConnectionError:
        print("❌ SANDBOX ERROR: VM not reachable")
        return None

    except Exception as e:
        print("❌ SANDBOX UNKNOWN ERROR:", e)
        return None
