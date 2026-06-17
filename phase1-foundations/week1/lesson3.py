

print("--- Port Scanner Preview ---")
ports = [80, 443, 22, 21, 3389]

for port in ports:
    if port == 80:
        print(f"Port {port} - HTTP")
    elif port == 443:
        print(f"Port {port} - HTTPS")
    elif port == 22:
        print(f"Port {port} - SSH")
    else:
        print(f"Port {port} - Unknown")

print()
print("--- Password Attempt Limiter ---")
correct_password = "python123"
attempts = 0
max_attempts = 3

while attempts < max_attempts:
    guess = input("Enter password: ")
    attempts = attempts + 1

    if guess == correct_password:
        print("Access Granted!")
        break
    else:
        remaining = max_attempts - attempts
        if remaining > 0:
            print(f"Wrong. {remaining} attempt(s) remaining.")
        else:
            print("Too many failed attempts. Locked out.")