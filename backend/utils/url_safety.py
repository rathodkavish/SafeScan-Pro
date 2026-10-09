"""
backend/utils/url_safety.py
URL Safety Guard for SafeScan-Pro
─────────────────────────────────
Prevents the backend from being used as an attack vector.

When SafeScan-Pro scans a malicious QR code, the backend visits the URL
for analysis. Without protection, an attacker could:

  1. SSRF — redirect to localhost/internal IPs to attack internal services
  2. IP Exposure — learn our server's IP from their access logs
  3. Large File — send a 10GB file to crash our server's memory
  4. Infinite Redirect — create a redirect loop to hang the server
  5. Non-HTTP Protocol — use file://, ftp://, gopher:// to access system files

This module validates ALL URLs before any HTTP request is made.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse


# ── Private / Reserved IP Ranges (SSRF Protection) ───────────────────────────
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),      # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),     # Private Class C
    ipaddress.ip_network("0.0.0.0/8"),          # Invalid
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space (CGNAT)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# ── Blocked Protocols ────────────────────────────────────────────────────────
ALLOWED_SCHEMES = {"http", "https"}

# ── Blocked Hostnames ────────────────────────────────────────────────────────
BLOCKED_HOSTNAMES = {
    "localhost", "0.0.0.0", "127.0.0.1", "::1",
    "metadata.google.internal",          # GCP metadata
    "169.254.169.254",                   # AWS/GCP/Azure metadata endpoint
    "metadata.google.com",
    "instance-data",                     # AWS legacy metadata
}

# ── Max Response Size (10 MB) ────────────────────────────────────────────────
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def validate_url(url: str) -> dict:
    """
    Validates a URL before the backend makes any HTTP request to it.

    Returns:
        {"safe": True} if URL is safe to visit
        {"safe": False, "reason": "..."} if URL should be blocked
    """
    if not url or not isinstance(url, str):
        return {"safe": False, "reason": "Empty or invalid URL"}

    # Strip whitespace and normalize
    url = url.strip()

    # ── 1. Protocol check ─────────────────────────────────────────────────
    parsed = urlparse(url if "://" in url else f"https://{url}")
    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        return {
            "safe": False,
            "reason": f"Blocked protocol: {scheme}:// — only HTTP/HTTPS allowed"
        }

    # ── 2. Hostname extraction ────────────────────────────────────────────
    hostname = parsed.hostname
    if not hostname:
        return {"safe": False, "reason": "No hostname found in URL"}

    hostname_lower = hostname.lower()

    # ── 3. Blocked hostnames ──────────────────────────────────────────────
    if hostname_lower in BLOCKED_HOSTNAMES:
        return {
            "safe": False,
            "reason": f"Blocked hostname: {hostname} — internal/reserved address"
        }

    # ── 4. IP address check ───────────────────────────────────────────────
    # Check if hostname is an IP address directly
    try:
        ip = ipaddress.ip_address(hostname)
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return {
                    "safe": False,
                    "reason": f"Blocked IP: {hostname} is in private/reserved range {network}"
                }
    except ValueError:
        # Not an IP address — it's a domain name, which is fine
        pass

    # ── 5. DNS resolution check — resolve hostname and verify IP ──────────
    try:
        resolved_ips = socket.getaddrinfo(hostname_lower, None, socket.AF_UNSPEC)
        for _, _, _, _, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                for network in BLOCKED_IP_RANGES:
                    if ip in network:
                        return {
                            "safe": False,
                            "reason": f"DNS rebinding attack: {hostname} resolves to private IP {ip_str}"
                        }
            except ValueError:
                pass
    except socket.gaierror:
        # DNS resolution failed — URL might be invalid, but let the request
        # itself handle the error. We don't block unknown domains.
        pass

    # ── 6. Port check — block non-standard ports that target services ─────
    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        return {
            "safe": False,
            "reason": f"Blocked port: {port} — only standard web ports allowed"
        }

    # ── 7. URL length check ───────────────────────────────────────────────
    if len(url) > 2048:
        return {
            "safe": False,
            "reason": "URL exceeds 2048 characters — potential buffer overflow attempt"
        }

    return {"safe": True}


def safe_url_or_raise(url: str):
    """
    Validates URL and raises ValueError if unsafe.
    Use this at the start of every function that makes HTTP requests.
    """
    result = validate_url(url)
    if not result["safe"]:
        raise ValueError(f"🛡 URL blocked by SafeScan security: {result['reason']}")
    return True


def ensure_https(url: str) -> str:
    """Add https:// if no scheme is present."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url
