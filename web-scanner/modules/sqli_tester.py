# modules/sqli_tester.py
# Tests for SQL injection vulnerabilities
# Sends test payloads and looks for database error messages in responses

import requests

# Payloads that commonly trigger SQL errors
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
]

# Error messages that appear in responses when SQL injection works
# Each tuple is (database_type, error_string_to_look_for)
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


def test_sqli(url, params=None):
    """
    Tests a URL for SQL injection vulnerabilities.
    Injects payloads into URL parameters and checks responses for DB errors.
    
    Args:
        url: target URL
        params: dict of parameters to test e.g. {"id": "1", "search": "test"}
                If None, tries to extract params from the URL itself.
    
    Returns:
        list of findings
    """
    print(f"\n[*] Testing for SQL injection on {url}...")

    findings = []

    # If no params provided, try common parameter names
    if not params:
        params = {"id": "1", "search": "test", "q": "test", "user": "test"}

    for param_name, original_value in params.items():
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                response = requests.get(url, params=test_params, timeout=5)
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