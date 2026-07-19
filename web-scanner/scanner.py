# scanner.py
# Web Vulnerability Scanner — main entry point

import datetime
import os
from modules.recon import get_target_info
from modules.header_checker import check_security_headers
from modules.path_scanner import scan_paths
from modules.path_scanner import scan_paths, fetch_robots


def generate_report(target, recon, headers, paths):
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
        f.write("=" * 50 + "\n")
        f.write("END OF REPORT\n")

    return filename


def main():
    print("=" * 50)
    print("  Web Vulnerability Scanner")
    print("  Educational use only")
    print("=" * 50)

    print("\nDefault target: http://testphp.vulnweb.com")
    custom = input("Press Enter to use default or type a URL: ").strip()

    target = custom if custom else "http://testphp.vulnweb.com"

    if not target.startswith("http"):
        target = "http://" + target

    # Run all modules
    recon = get_target_info(target)

    if not recon["reachable"]:
        print("\n[-] Target unreachable. Exiting.")
        return

    headers = check_security_headers(target)
    paths = scan_paths(target)
    robots = fetch_robots(target)

    # Generate report
    print("\n[*] Generating report...")
    filename = generate_report(target, recon, headers, paths)
    print(f"[+] Report saved to: {filename}")

    # Summary
    missing_high = [h for h in headers if not h["present"] and h["severity"] == "HIGH"]
    interesting_paths = [p for p in paths if p["interesting"]]

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"High severity header issues: {len(missing_high)}")
    print(f"Interesting paths found:     {len(interesting_paths)}")
    print(f"Full report:                 {filename}")


if __name__ == "__main__":
    main()