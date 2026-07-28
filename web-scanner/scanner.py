# scanner.py
# Web Vulnerability Scanner — main entry point

import datetime
import os
import re
import requests
from modules.recon import get_target_info
from modules.header_checker import check_security_headers
from modules.path_scanner import scan_paths, fetch_robots
from modules.sqli_tester import test_sqli
from modules.xss_tester import test_xss
from modules.traversal_tester import test_traversal


def generate_report(target, recon, headers, paths, vulns):
    """
    Generates a timestamped text report of all findings.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/scan_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("WEB VULNERABILITY SCANNER REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target:  {target}\n")
        f.write(f"Date:    {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n")

        # Recon section
        f.write("-" * 50 + "\n")
        f.write("RECONNAISSANCE\n")
        f.write("-" * 50 + "\n")
        f.write(f"Status Code:    {recon['status_code']}\n")
        f.write(f"Server:         {recon['server'] or 'Not disclosed'}\n")
        f.write(f"Content-Type:   {recon['content_type'] or 'Unknown'}\n")
        f.write(f"Content-Length: {recon['content_length']} chars\n")

        if recon["technologies"]:
            f.write(f"Technologies:   {', '.join(recon['technologies'])}\n")

        if recon["redirect_url"]:
            f.write(f"Redirects to:   {recon['redirect_url']}\n")

        f.write("\n")

        # Headers section
        f.write("-" * 50 + "\n")
        f.write("SECURITY HEADERS\n")
        f.write("-" * 50 + "\n")

        missing = [h for h in headers if not h["present"]]
        present = [h for h in headers if h["present"]]

        f.write(f"Present: {len(present)}/{len(headers)}\n\n")

        for h in missing:
            f.write(f"[MISSING] [{h['severity']}] {h['header']}\n")
            f.write(f"          {h['description']}\n")

        f.write("\n")

        # Paths section
        f.write("-" * 50 + "\n")
        f.write("PATH SCAN\n")
        f.write("-" * 50 + "\n")

        interesting = [p for p in paths if p["interesting"]]

        if interesting:
            for p in interesting:
                f.write(f"[{p['status_code']}] {p['label']:10} {p['url']}\n")
        else:
            f.write("No interesting paths found.\n")

        f.write("\n")

        # Vulnerabilities section
        f.write("-" * 50 + "\n")
        f.write("VULNERABILITIES\n")
        f.write("-" * 50 + "\n")

        if vulns:
            for v in vulns:
                f.write(f"[!] {v['type']}\n")
                f.write(f"    Parameter: {v['parameter']}\n")
                f.write(f"    Payload:   {v['payload']}\n")
                f.write(f"    Evidence:  {v['evidence']}\n")
                f.write(f"    URL:       {v['url']}\n\n")
        else:
            f.write("No vulnerabilities detected.\n")

        f.write("\n")
        f.write("=" * 50 + "\n")
        f.write("END OF REPORT\n")

    return filename


def get_dvwa_session(base_url):
    """
    Logs into DVWA and returns an authenticated session object.
    A session automatically carries cookies across all requests.
    """
    session = requests.Session()
    login_url = f"{base_url}/login.php"

    # First GET to grab the CSRF token DVWA requires
    response = session.get(login_url, timeout=5)

    # Extract user_token from the login form
    token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", response.text)
    token = token_match.group(1) if token_match else ""

    # POST login credentials
    session.post(login_url, data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    })

    print("[+] Authenticated with DVWA")
    return session


def main():
    print("=" * 50)
    print("  Web Vulnerability Scanner")
    print("  Educational use only")
    print("=" * 50)

    print("\nDefault target: http://localhost")
    custom = input("Press Enter to use default or type a URL: ").strip()

    target = custom if custom else "http://localhost"

    if not target.startswith("http"):
        target = "http://" + target

    # Run recon modules
    recon = get_target_info(target)

    if not recon["reachable"]:
        print("\n[-] Target unreachable. Exiting.")
        return

    headers = check_security_headers(target)
    paths = scan_paths(target)
    robots = fetch_robots(target)

    # Authenticate and run vulnerability tests
    print("\n[*] Running targeted vulnerability tests...")
    session = get_dvwa_session(target)

    sqli_findings = test_sqli(
        "http://localhost/vulnerabilities/sqli/",
        params={"id": "1", "Submit": "Submit"},
        session=session
    )

    xss_findings = test_xss(
        "http://localhost/vulnerabilities/xss_r/",
        params={"name": "test"},
        session=session
    )

    traversal_findings = test_traversal(
        "http://localhost/vulnerabilities/fi/",
        params={"page": "include.php"},
        session=session
    )

    vuln_findings = sqli_findings + xss_findings + traversal_findings

    # Generate report
    print("\n[*] Generating report...")
    filename = generate_report(target, recon, headers, paths, vuln_findings)
    print(f"[+] Report saved to: {filename}")

    # Summary
    missing_high = [h for h in headers if not h["present"] and h["severity"] == "HIGH"]
    interesting_paths = [p for p in paths if p["interesting"]]

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"High severity header issues: {len(missing_high)}")
    print(f"Interesting paths found:     {len(interesting_paths)}")
    print(f"Vulnerabilities found:       {len(vuln_findings)}")
    print(f"Full report:                 {filename}")


if __name__ == "__main__":
    main()