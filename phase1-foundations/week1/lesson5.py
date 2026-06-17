import random
import string

def generate_password(length):
    """
    Generates a random password of given length.
    Uses uppercase, lowercase, digits and special characters.
    """   
    characters = string.ascii_letters + string.digits + "!@#$%&*?"
    password = ""

    for i in range(length):
        password += random.choice(characters)

    return password


def get_valid_length():
    """
    Asks the user for a password length with error handling.
    Keeps asking until a valid integer between 8 and 64 is entered.
    """

    while True:
        try:
            length = int(input("Enter password length (8-64): "))
            if length < 8:
                print("Minimum length is 8.")
            elif length > 64:
                print("Maximum length is 64.")
            else:
                return length
        except ValueError:
            print("Please enter a Whole number.")


# --- Main ---
print("=== Password Generator ===")
print()

while True:
    length = get_valid_length()
    password = generate_password(length)

    print(f"\nGenerated password: {password}")
    print(f"Length: {length} characters")

    verify = input("Verify your new password: ")
    if verify == password:
        print("Password successfully verified")
    else:
        print("Password does not match")
        

    again = input("\nGenerate another? (yes/no): ").lower()
    if again != "yes":
        print("Goodbye.")
        break

