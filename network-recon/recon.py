# network-recon/recon.py
# Full network reconnaissance tool
# Educational use only — only scan systems you own or have permission to test

import socket
import subprocess
import platform
import requests
import datetime
import os


# ── DNS Resolution ─────────────────────────────────────────

def resolve_dns(hostname):
    """
    Resolves a hostname to an IP address.
    Returns the IP string or None if resolution fails.
    """
    try:
        ip = socket.gethostbyname(hostname)
        print(f"[+] DNS resolved: {hostname} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] DNS resolution failed for {hostname}")
        return None


# ── Ping & TTL OS Detection ────────────────────────────────

def ping_host(host):
    """
    Pings a host and returns (alive, ttl).
    Estimates OS from TTL value:
      64  → Linux/macOS
      128 → Windows
      255 → Network device
    """
    system = platform.system()
    command = ["ping", "-n", "1", host] if system == "Windows" else ["ping", "-c", "1", host]

    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    alive = result.returncode == 0
    ttl = None
    os_guess = "Unknown"

    if alive:
        output = result.stdout
        # Extract TTL from ping output
        for part in output.split():
            if "ttl=" in part.lower():
                try:
                    ttl = int(part.split("=")[1])
                except ValueError:
                    pass

        if ttl:
            if ttl <= 64:
                os_guess = "Linux / macOS"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Network device"

        print(f"[+] Host is UP — TTL={ttl} → likely {os_guess}")
    else:
        print(f"[-] Host is DOWN or not responding to ping")

    return alive, ttl, os_guess


# ── Port Scanner ───────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}


def scan_ports(host):
    """
    Scans common ports on a host.
    Returns list of open port findings.
    """
    print(f"\n[*] Scanning {len(COMMON_PORTS)} ports on {host}...")
    open_ports = []

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                print(f"[OPEN]   Port {port:5} → {service}")
                open_ports.append({"port": port, "service": service})
        except socket.error:
            pass

    if not open_ports:
        print("[-] No open ports found")

    return open_ports



def grab_banner(host, port):
    """
    Attempts to grab the service banner from an open port.
    Handles SSH (sends immediately) differently from HTTP services.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))

        # SSH sends banner immediately on connect — just receive
        if port == 22:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner

        # HTTP services need a request to respond
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner

    except Exception:
        return None


# ── HTTP Header Grab ───────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]


def grab_http_info(host, ports):
    """
    If port 80 or 443 is open, grabs HTTP headers and checks security headers.
    """
    open_port_numbers = [p["port"] for p in ports]
    findings = {}

    for port in [443, 80]:
        if port in open_port_numbers:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{host}"

            try:
                print(f"\n[*] Grabbing HTTP info from {url}...")
                response = requests.get(url, timeout=5, verify=False)
                headers = response.headers

                findings["url"] = url
                findings["status_code"] = response.status_code
                findings["server"] = headers.get("Server", "Not disclosed")
                findings["powered_by"] = headers.get("X-Powered-By", None)

                missing = []
                present = []
                for h in SECURITY_HEADERS:
                    if h in headers:
                        present.append(h)
                    else:
                        missing.append(h)

                findings["headers_present"] = present
                findings["headers_missing"] = missing

                print(f"[+] Status: {response.status_code}")
                print(f"[+] Server: {findings['server']}")
                if missing:
                    print(f"[-] Missing security headers: {', '.join(missing)}")

            except Exception as e:
                print(f"[-] HTTP grab failed: {e}")

            break

    return findings


# ── Report Generator ───────────────────────────────────────

def generate_report(target, ip, alive, ttl, os_guess, open_ports, http):
    """Saves full findings to a timestamped report file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/recon_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("NETWORK RECON REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target:    {target}\n")
        f.write(f"IP:        {ip}\n")
        f.write(f"Date:      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("-" * 50 + "\n")
        f.write("HOST DISCOVERY\n")
        f.write("-" * 50 + "\n")
        f.write(f"Status:    {'UP' if alive else 'DOWN'}\n")
        f.write(f"TTL:       {ttl}\n")
        f.write(f"OS Guess:  {os_guess}\n\n")

        f.write("-" * 50 + "\n")
        f.write("OPEN PORTS\n")
        f.write("-" * 50 + "\n")
        if open_ports:
            for p in open_ports:
                f.write(f"  {p['port']:5} → {p['service']}\n")
                if p.get("banner"):
                    f.write(f"          Banner: {p['banner']}\n")
        else:
            f.write("  None found\n")
        f.write("\n")

        if http:
            f.write("-" * 50 + "\n")
            f.write("HTTP FINDINGS\n")
            f.write("-" * 50 + "\n")
            f.write(f"URL:       {http.get('url')}\n")
            f.write(f"Status:    {http.get('status_code')}\n")
            f.write(f"Server:    {http.get('server')}\n")
            if http.get("powered_by"):
                f.write(f"Powered by: {http.get('powered_by')}\n")
            if http.get("headers_missing"):
                f.write(f"Missing headers: {', '.join(http['headers_missing'])}\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write("END OF REPORT\n")

    return filename


# ── Main ───────────────────────────────────────────────────

def main():
    print("=" * 50)
    print("  Network Recon Tool")
    print("  Educational use only")
    print("=" * 50)
    print()

    target = input("Enter target hostname or IP: ").strip()

    # Step 1 — DNS
    ip = resolve_dns(target)
    if not ip:
        return

    # Step 2 — Ping
    print(f"\n[*] Pinging {ip}...")
    alive, ttl, os_guess = ping_host(ip)

    # Step 3 — Port scan
    open_ports = scan_ports(ip)

    # Banner grabbing on open ports
    if open_ports:
        print(f"\n[*] Grabbing banners from open ports...")
        for entry in open_ports:
            banner = grab_banner(ip, entry["port"])
            if banner:
                first_line = banner.split("\n")[0]
                print(f"[+] Port {entry['port']} banner: {first_line}")
                entry["banner"] = first_line
            else:
                entry["banner"] = None

    # Step 4 — HTTP info if web ports open
    http = grab_http_info(ip, open_ports)

    # Step 5 — Report
    print("\n[*] Generating report...")
    filename = generate_report(target, ip, alive, ttl, os_guess, open_ports, http)
    print(f"[+] Report saved to: {filename}")

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Target:     {target} ({ip})")
    print(f"Status:     {'UP' if alive else 'DOWN'}")
    print(f"OS Guess:   {os_guess}")
    print(f"Open ports: {len(open_ports)}")
    print(f"Report:     {filename}")


if __name__ == "__main__":
    main()