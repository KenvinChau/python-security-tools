# modules/recon.py
# Initial reconnaissance - gather basic target information

import requests

def get_target_info(url):
    """
    Performs initial recon on a target URL.
    Returns a dictionary of discovered information.
    """
    print(f"\n[*] Starting recon on {url}")

    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "redirect_url": None,
        "technologies": []
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["content_length"] = len(response.text)

        # Extract headers
        headers = response.headers

        if "Server" in headers:
            result["server"] = headers["Server"]

        if "Content-Type" in headers:
            result["content_type"] = headers["Content-Type"]

        # Detect redirect
        if response.url != url:
            result["redirect_url"] = response.url




        # Basic technology detection from headers
        if "X-Powered-By" in headers:
            result["technologies"].append(headers["X-Powered-By"])

        if "X-Generator" in headers:
            result["technologies"].append(headers["X-Generator"])

        print(f"[+] Target reachable — status {response.status_code}")

        if result["server"]:
            print(f"[+] Server: {result['server']}")

        if result["technologies"]:
            print(f"[+] Technologies: {', '.join(result['technologies'])}")

        if result["redirect_url"]:
            print(f"[+] Redirects to: {result['redirect_url']}")




    except requests.ConnectionError:
        print(f"[-] Target unreachable — connection error")
    except requests.Timeout:
        print(f"[-] Target unreachable — timeout")

    return result