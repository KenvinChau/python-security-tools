# modules/xss_tester.py
import requests
import uuid

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "'><script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "<svg onload=alert('xss')>",
    "javascript:alert('xss')",
]

XSS_INDICATORS = [
    "<script>alert(",
    "onerror=alert(",
    "<svg onload=",
    "javascript:alert(",
]


def test_xss(url, params=None, session=None):
    """
    Tests a URL for reflected XSS vulnerabilities.
    Pass a requests.Session object if the target requires authentication.
    """
    print(f"\n[*] Testing for XSS on {url}...")

    client = session if session else requests

    findings = []

    if not params:
        params = {"search": "test", "q": "test", "query": "test", "id": "1"}

    for param_name, original_value in params.items():
        for payload in XSS_PAYLOADS:
            marker = str(uuid.uuid4())[:8]
            marked_payload = payload.replace("xss", marker)

            test_params = params.copy()
            test_params[param_name] = marked_payload

            try:
                response = client.get(url, params=test_params, timeout=5)
                body = response.text

                if marker in body:
                    for indicator in XSS_INDICATORS:
                        sanitised_indicator = indicator.replace("xss", marker)
                        if sanitised_indicator in body:
                            finding = {
                                "type": "Reflected XSS",
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": "Payload reflected unencoded in response",
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