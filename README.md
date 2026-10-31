# Python Security Tools

Small command-line security tools written in Python, using only the standard library.

## Tools

| Tool | What it does |
|---|---|
| **Password Strength Analyser** | Scores a password out of 7 on length, character variety and special characters, and suggests improvements. |
| **Password Generator** | Generates random passwords with input validation and error handling. |
| **Port Scanner** | Scans a host for open ports, identifies common services, and saves a timestamped report. Built on Python's `socket` module. |

## Usage

Each tool is a standalone script in this repository. Clone the repo, then run the script for the tool you want with `python3` followed by the file name.

```bash
git clone https://github.com/KenvinChau/python-security-tools
cd python-security-tools
```

Requires Python 3. No external dependencies.

## Related projects

More security projects, including a web vulnerability scanner (SQL injection, XSS and directory traversal detection) and a network reconnaissance toolkit (DNS, OS fingerprinting, port scanning), are available on my [GitHub profile](https://github.com/KenvinChau?tab=repositories).

## Possible improvements

- Multithreaded port scanning for speed
- Checking passwords against a list of known breached passwords

## Legal notice

For educational use. Only scan systems you own or have explicit permission to test.
