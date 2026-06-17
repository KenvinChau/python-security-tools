

def scan_port(port):
    """
    Takes a port number and returns the service name.
    Returns 'Unknown' if port is not in the database.
    """

    port_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt"
    }

    if port in port_map:
        return port_map[port]
    else:
        return "Unknown"
    
print("=== Port Scanner ===")
ports_to_scan = [22, 80, 443, 8080, 9999, 3306]

for port in ports_to_scan:
    service = scan_port(port)
    print(f"Port {port:5} -> {service}")