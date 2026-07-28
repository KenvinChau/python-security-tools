# modules/sqli_tester.py
import requests

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
]

SQLI_ERRORS = [
    ("MySQL",      "you have an error in your sql syntax"),
    ("MySQL",      "warning: mysql"),
    ("MySQL",      "mysql_fetch"),
    ("PostgreSQL", "pg_query"),
    ("PostgreSQL", "pg_exec"),
    ("MSSQL",      "unclosed quotation mark"),
    ("MSSQL",      "microsoft sql server"),
    ("Oracle",     "ora-01756"),
    ("SQLite",     "sqlite3.operationalerror"),
    ("Generic",    "sql syntax"),
    ("Generic",    "syntax error"),
    ("Generic",    "unexpected token"),
    ("Generic",    "unterminated string"),
]


def test_sqli(url, params=None, session=None):
    """
    Tests a URL for SQL injection vulnerabilities.
    Pass a requests.Session object if the target requires authentication.
    """
    print(f"\n[*] Testing for SQL injection on {url}...")

    # Use the authenticated session if provided, otherwise use plain requests
    client = session if session else requests

    findings = []

    if not params:
        params = {"id": "1", "search": "test", "q": "test", "user": "test"}

    for param_name, original_value in params.items():
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                response = client.get(url, params=test_params, timeout=5)
                body = response.text.lower()

                for db_type, error_string in SQLI_ERRORS:
                    if error_string in body:
                        finding = {
                            "type": "SQL Injection",
                            "parameter": param_name,
                            "payload": payload,
                            "db_type": db_type,
                            "evidence": error_string,
                            "url": response.url
                        }
                        findings.append(finding)
                        print(f"[!] POSSIBLE SQLi — param={param_name} payload={payload}")
                        print(f"    DB error detected: {error_string} ({db_type})")
                        break

            except requests.RequestException:
                pass

    if not findings:
        print(f"[-] No SQL injection indicators found")

    return findings