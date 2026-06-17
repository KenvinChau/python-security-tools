def analyse_password(password):

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 8 characters.")

    has_number = False
    for char in password:
        if char.isdigit():
            has_number = True
            break
    
    if has_number:
        score += 1
    else:
        feedback.append("Add at least one number.")

####

    has_upper = False
    for char in password:
        if char.isupper():
            has_upper = True
            break
    
    if has_upper:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

####

    has_lower = False
    for char in password:
        if char.islower():
            has_lower = True
            break
    
    if has_lower:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

####

    special_chars = ["!", "@", "#", "$", "%", "&", "*", "?"]

    has_special = False
    for char in password:
        if char in special_chars:
            has_special = True
            break

    if has_special:
        score += 2
    else:
        feedback.append("Add a special character like !, @, #, $.")

    return score, feedback

# --- Main Program ---

print("=== Password Strength Analyser ===")
print()



while True:
    password = input("Enter a password to analyse (or type 'quit' to exit): ")

    if password == "quit":
        print("Goodbye.")
        break

    score, feedback = analyse_password(password)

    print()
    print(f"Password: {'*' * len(password)}")
    print(f"Score:    {score}/7")

    if score <= 2:
        print("Strength:  WEAK")
    elif score <= 4:
        print("Strength:  MODERATE")
    elif score <= 6:
        print("Strength:  STRONG")
    else:
        print("Strength:  VERY STRONG")

    if feedback:
        print()
        print("Suggestions:")
        for tip in feedback:
            print(f" - {tip}")
    
    print()

