"""
# Lesson 1 - Variables, f-strings, and User Input

# Ask the user for their details
name = input("Enter your name: ")
age = input("Enter your age: ")
city = input("Enter your city: ")

# Print a formatted summary
print()  # blank line for spacing
print("--- Profile Summary ---")
print(f"Name:  {name.capitalize()}")
print(f"Age:   {age}")
print(f"City:  {city.upper()}")
print(f"Name has {len(name)} characters.")

print(type(age))
print(type(20))




age = int(input("Enter your age: "))
print(f"In 10 years you will be {age + 10}.")

"""

age = 20

if age < 13:
    print("You are a child")
elif age < 18:
    print("You are a teenager.")
else:
    print("You are an adult")