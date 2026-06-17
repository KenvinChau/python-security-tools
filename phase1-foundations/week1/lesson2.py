"""
name = input("Enter you name: ")
age = int(input("Enter you age: "))
password = input("Create a password: ")

if age < 18:
    print(f"Sorry {name.capitalize()}, you must be 18 or older.")
elif age > 100:
    print("That age doesn't seem right.")
else: 
    print(f"Welcome, {name.capitalize()}!")

if len(password) < 6:
    print("Weak password — too short.")
elif len(password) < 10:
    print("Okay password — could be longer.")
else:
    print("Good password length.")

passconfirm = input("re-enter password to confirm: ")

if passconfirm == password:
    print("Password Created")
else:
    print("Invalid")

    """

ports = [80, 443, 22, 21, 3389]

for port in ports:
    print(f"checking port {port}...")

for i in range(5):
    print(i)

attempts = 0

while attempts < 3:
    print(f"Attempt {attempts + 1}")
    attempts = attempts + 1