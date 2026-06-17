# Project 2 - Port Scanner (v2)
# Scans common ports and saves results to a file

import socket
import datetime
import os


def get_service(port):
    """Returns the known service name for a given port number."""
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")


def scan_port(host, port):
    """
    Attempts to connect to a given host and port.
    Returns True if port is open, False if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def run_scanner(host, ports):
    """
    Scans a list of ports on the given host.
    Prints results and saves them to a timestamped file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    start_time = datetime.datetime.now()

    header = (
        f"=== Port Scan Report ===\n"
        f"Target:  {host}\n"
        f"Ports:   {len(ports)} scanned\n"
        f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'-' * 40}\n"
    )

    print(header)

    open_ports = []
    results = []

    for port in ports:
        service = get_service(port)
        is_open = scan_port(host, port)

        if is_open:
            line = f"[OPEN]   Port {port:5} → {service}"
            open_ports.append(port)
        else:
            line = f"[closed] Port {port:5} → {service}"

        print(line)
        results.append(line)

    duration = (datetime.datetime.now() - start_time).seconds

    summary = (
        f"{'-' * 40}\n"
        f"Scan complete in {duration}s.\n"
        f"Open ports ({len(open_ports)}): {open_ports if open_ports else 'None'}\n"
    )

    print(summary)

    # Save results to file
    os.makedirs("scan_results", exist_ok=True)
    filename = f"scan_results/scan_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(header)
        for line in results:
            f.write(line + "\n")
        f.write(summary)

    print(f"Results saved to: {filename}")


# --- Main ---
TARGET = "127.0.0.1"

COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    3306, 3389, 5432, 8080, 8443
]

print("=== Python Port Scanner v2 ===")
print("Scanning localhost only — educational use.\n")

run_scanner(TARGET, COMMON_PORTS)