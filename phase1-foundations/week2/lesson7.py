import subprocess
import platform


def run_command(command):
    """
    Runs a shell command and returns the output.
    Returns None if the command fails.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "Error: command timed out"
    except FileNotFoundError:
        return "Error: command not found"

def ping_host(host):
    """
    Pings a host once and returns whether it responded.
    Handles both Windows and Linux ping syntax.
    """
    system = platform.system()

    if system == "Windows":
        command = ["ping", "-n", "1", host]
    else:
        command = ["ping", "-c", "1", host]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10
    )

    return result.returncode == 0


# --- Main ---
print("=== System Recon Tool ===")
print()


# Basic system info
print("[*] Gathering system information...")
print()


# Works on both Windows and Linux
system = platform.system()
print(f"OS: {platform.system()} {platform.release()}")
print(f"Machine: {platform.machine()}")


if system == "Windows":
    whoami = run_command(["whoami"])
    print(f"Current user: {whoami}")

    hostname = run_command(["hostname"])
    print(f"Hostname: {hostname}")

    ipconfig = run_command(["ipconfig"])
    print(f"\nNetwork info:\n{ipconfig}")

# Commands that work on Linux/WSL
else:
    whoami = run_command(["whoami"])
    print(f"Current user: {whoami}")

    hostname = run_command(["hostname"])
    print(f"Hostname: {hostname}")

    ifconfig = run_command(["ip", "addr", "show"])
    print(f"\nNetwork info:\n{ifconfig}")

print("\n[*] Ping test...")
hosts = ["google.com", "github.com", "192.168.1.1"]

for host in hosts:
    alive = ping_host(host)
    status = "UP" if alive else "DOWN"
    print(f" {host:20} → {status}")