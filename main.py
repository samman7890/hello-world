
import random

# Caesar cipher for educational use only
def encrypt(password, shift=3):
    encrypted = ''
    for char in password:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                encrypted += chr(shifted)
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                encrypted += chr(shifted)
        else:
            encrypted += char
    return encrypted

def decrypt(encrypted_password, shift=3):
    decrypted = ''
    for char in encrypted_password:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
                decrypted += chr(shifted)
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
                decrypted += chr(shifted)
        else:
            decrypted += char
    return decrypted

# Password vault
vault = {}

def add_password(website, username, password):
    encrypted_password = encrypt(password)
    vault[website] = {'username': username, 'password': encrypted_password}
    print(f"Password for {website} added successfully.")

def get_password(website):
    if website in vault:
        username = vault[website]['username']
        encrypted_password = vault[website]['password']
        password = decrypt(encrypted_password)
        print(f"Website: {website}")
        print(f"Username: {username}")
        print(f"Password: {password}")
    else:
        print("No entry found for that website.")

def save_passwords(filename="vault.txt"):
    with open(filename, "w") as f:
        for site in vault:
            username = vault[site]['username']
            encrypted_password = vault[site]['password']
            f.write(f"{site},{username},{encrypted_password}\n")
    print("Passwords saved to file.")

def load_passwords(filename="vault.txt"):
    try:
        with open(filename, "r") as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 3:
                    site, username, encrypted_password = parts
                    vault[site] = {'username': username, 'password': encrypted_password}
        print("Passwords loaded from file.")
    except FileNotFoundError:
        print("No saved password file found.")

# OPTIONAL: Password strength checker
def is_strong_password(password):
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol

# OPTIONAL: Password generator
def generate_password(length=12):
    if length < 8:
        print("Password should be at least 8 characters long.")
        return ''
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(random.choice(chars) for _ in range(length))

# Example interface (for testing)
if __name__ == "__main__":
    load_passwords()
    while True:
        print("\n1. Add password")
        print("2. Get password")
        print("3. Save passwords")
        print("4. Generate password (optional)")
        print("5. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            site = input("Website: ")
            user = input("Username: ")
            pwd = input("Password: ")
            if not is_strong_password(pwd):
                print("Warning: Weak password. Consider using a stronger one.")
            add_password(site, user, pwd)
        elif choice == "2":
            site = input("Website: ")
            get_password(site)
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            print("Generated password:", generate_password())
        elif choice == "5":
            break
        else:
            print("Invalid choice.")
