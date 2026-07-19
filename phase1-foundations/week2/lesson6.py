# Lesson 6 - requests and hashlib

import requests
import hashlib


def check_website(url):
    """
    Makes a GET request to a URL and returns status info.
    """
    try:
        response = requests.get(url, timeout=5)
        return {
            "url": url,
            "status_code": response.status_code,
            "reachable": True,
            "content_length": len(response.text)
        }
    except requests.ConnectionError:
        return {"url": url, "reachable": False, "status_code": None, "content_length": 0}
    except requests.Timeout:
        return {"url": url, "reachable": False, "status_code": "timeout", "content_length": 0}


def hash_text(text, algorithm="sha256"):
    """
    Hashes a string using the specified algorithm.
    Supports md5, sha1, sha256, sha512.
    """
    text_bytes = text.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(text_bytes).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(text_bytes).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(text_bytes).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(text_bytes).hexdigest()
    else:
        return "Unsupported algorithm"


# --- Main ---
print("=== Web Checker ===")
print()

urls = [
    "https://google.com",
    "https://github.com",
    "https://thiswebsitedoesnotexist12345.com"
]

for url in urls:
    result = check_website(url)
    if result["reachable"]:
        print(f"[{result['status_code']}] {result['url']} — {result['content_length']} chars")
    else:
        print(f"[UNREACHABLE] {result['url']}")

print()
print("=== Hash Demo ===")
print()

password = input("Enter a password to hash: ")

for algo in ["md5", "sha1", "sha256", "sha512"]:
    hashed = hash_text(password, algo)
    print(f"{algo.upper():8} → {hashed}")

print()
print("Notice: same input always produces same hash.")
print("Notice: different algorithms produce different length outputs.")