# modules/header_checker.py
# Check for presence of important HTTP security headers

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS attacks",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "severity": "LOW"
    }
}

def check_security_headers(url):
    """
    Checks a URL for the presence of important security headers.
    Returns a list of findings.
    """ 
    print(f"\n[*] Checking security headers...")

    findings = []

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                findings.append({
                    "header": header,
                    "present": True,
                    "value": headers[header],
                    "severity": "PASS",
                    "description": info["description"]
                })
                print(f"[+] PRESENT  {header}")
            else:
                findings.append({
                    "header": header,
                    "present": False,
                    "value": None,
                    "severity": info["severity"],
                    "description": info["description"]
                })
                print(f"[-] MISSING  [{info['severity']}] {header} — {info['description']}")

    except requests.RequestException as e:
        print(f"[-] Header check failed: {e}")

    return findings




