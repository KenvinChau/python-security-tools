# modules/xss_tester.py
# Tests for reflected XSS vulnerabilities
# Injects a unique marker and checks if it appears unencoded in the response

import requests
import uuid

# XSS payloads — chosen to be detectable without being harmful
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "'><script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "<svg onload=alert('xss')>",
    "javascript:alert('xss')",
]

# If any of these appear in the response, the payload was NOT sanitised
XSS_INDICATORS = [
    "<script>alert(",
    "onerror=alert(",
    "<svg onload=",
    "javascript:alert(",
]


def test_xss(url, params=None):
    """
    Tests a URL for reflected XSS vulnerabilities.
    Injects payloads and checks if they appear unencoded in the response.

    Reflected XSS = the payload is sent in the request and reflected
    back in the response. The most common and detectable type.

    Args:
        url: target URL  
        params: dict of parameters to test

    Returns:
        list of findings
    """
    print(f"\n[*] Testing for XSS on {url}...")

    findings = []

    if not params:
        params = {"search": "test", "q": "test", "query": "test", "id": "1"}

    for param_name, original_value in params.items():
        for payload in XSS_PAYLOADS:

            # Add a unique marker so we can confirm OUR payload reflected
            marker = str(uuid.uuid4())[:8]
            marked_payload = payload.replace("xss", marker)

            test_params = params.copy()
            test_params[param_name] = marked_payload

            try:
                response = requests.get(url, params=test_params, timeout=5)
                body = response.text

                # Check if our unique marker came back unencoded
                if marker in body:
                    # Check if it's inside an executable context
                    for indicator in XSS_INDICATORS:
                        sanitised_indicator = indicator.replace("xss", marker)
                        if sanitised_indicator in body:
                            finding = {
                                "type": "Reflected XSS",
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Payload reflected unencoded in response",
                                "url": response.url
                            }
                            findings.append(finding)
                            print(f"[!] POSSIBLE XSS — param={param_name}")
                            print(f"    Payload reflected unencoded in response body")
                            break

            except requests.RequestException:
                pass

    if not findings:
        print(f"[-] No XSS indicators found")

    return findings