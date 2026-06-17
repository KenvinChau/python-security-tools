try:
    number = int(input("Enter a number: "))
    print(f"Double: {number * 2}")
except ValueError:
    print("That wasn't a valid number.")


try:
    result = 10 / 0
except ZeroDivisionError:
    print("Can't divide by zero.")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    print("This runs no matter what.")

import random
import string
import os

print(random.randint(1, 100))      # random number between 1 and 100
print(string.ascii_letters)        # all letters a-z A-Z
print(os.getcwd())                 # current working directory

