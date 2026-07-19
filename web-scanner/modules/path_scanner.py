# modules/path_scanner.py
# Scan for commonly exposed or sensitive paths

import requests


COMMON_PATHS = [
    "/admin",
    "/admin/login",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/backup",
    "/config",
    "/dashboard",
    "/api",
    "/api/v1",
    "/robots.txt",
    "/sitemap.xml",
    "/.git",
    "/server-status",
    "/test",
    "/debug",
    "/uploads",
]


def scan_paths(base_url):
    """
    Scans a list of common paths against the target.
    Returns a list of findings with status codes.
    """
    print(f"\n[*] Scanning {len(COMMON_PATHS)} common paths...")

    findings = []

    for path in COMMON_PATHS:
        url = base_url.rstrip("/") + path

        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            status = response.status_code

            # 200 = found, 301/302 = redirect (interesting), 403 = forbidden (exists but protected)
            if status == 200:
                label = "FOUND"
            elif status in [301, 302]:
                label = "REDIRECT"
            elif status == 403:
                label = "FORBIDDEN"
            else:
                label = "not found"

            finding = {
                "path": path,
                "url": url,
                "status_code": status,
                "label": label,
                "interesting": status in [200, 301, 302, 403]
            }

            findings.append(finding)

            if finding["interesting"]:
                print(f"[{status}] {label:10} {path}")

        except requests.RequestException:
            pass

    return findings




def fetch_robots(base_url):
    """
    Fetches and prints robots.txt if it exists.
    Often reveals hidden paths the site owner wants to keep private.
    """
    url = base_url.rstrip("/") + "/robots.txt"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"\n[+] robots.txt contents:")
            print("-" * 30)
            print(response.text.strip())
            print("-" * 30)
            return response.text
    except requests.RequestException:
        pass
    return None