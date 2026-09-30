import os
import json
import re
import math
import secrets
import string
import getpass
import base64
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ============================================================
# CONFIGURATION
# ============================================================

VAULT_FILE = "secure_vault.dat"

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "password123",
    "admin123"
}


# ============================================================
# SECURITY FUNCTIONS
# ============================================================

def derive_key(master_password, salt):
    """
    Converts the master password into a cryptographic key.
    Scrypt is designed to make password guessing more expensive.
    """

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    key = kdf.derive(master_password.encode())

    return key


def calculate_entropy(password):
    """
    Gives an approximate password entropy value.
    """

    character_pool = 0

    if re.search(r"[a-z]", password):
        character_pool += 26

    if re.search(r"[A-Z]", password):
        character_pool += 26

    if re.search(r"[0-9]", password):
        character_pool += 10

    if re.search(r"[^A-Za-z0-9]", password):
        character_pool += 32

    if character_pool == 0:
        return 0

    entropy = len(password) * math.log2(character_pool)

    return round(entropy, 2)


def check_password_strength(password):
    """
    Analyzes the password and returns a score and security level.
    """

    score = 0
    problems = []

    # Length
    if len(password) >= 16:
        score += 2
    elif len(password) >= 12:
        score += 1
    else:
        problems.append("Use at least 12 characters.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        problems.append("Add lowercase letters.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        problems.append("Add uppercase letters.")

    # Numbers
    if re.search(r"[0-9]", password):
        score += 1
    else:
        problems.append("Add numbers.")

    # Special characters
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        problems.append("Add special characters.")

    # Common password
    if password.lower() in COMMON_PASSWORDS:
        score -= 3
        problems.append("This is a commonly used password.")

    # Repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 1
        problems.append("Avoid repeating the same character many times.")

    # Sequential numbers
    if "123" in password or "456" in password or "789" in password:
        score -= 1
        problems.append("Avoid predictable number sequences.")

    # Keep score between 0 and 7
    score = max(0, min(score, 7))

    if score <= 1:
        level = "Very Weak"
    elif score <= 3:
        level = "Weak"
    elif score <= 4:
        level = "Moderate"
    elif score <= 5:
        level = "Strong"
    elif score <= 6:
        level = "Very Strong"
    else:
        level = "Excellent"

    entropy = calculate_entropy(password)

    return score, level, entropy, problems


# ============================================================
# PASSWORD GENERATOR
# ============================================================

def generate_password(length=20):

    if length < 12:
        length = 12

    characters = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    return password


# ============================================================
# AUDIT LOG
# ============================================================

def audit_log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("security_audit.log", "a", encoding="utf-8") as file:
        file.write(f"[{timestamp}] {message}\n")


# ============================================================
# VAULT FUNCTIONS
# ============================================================

def create_new_vault():

    print("\n===== CREATE SECURE VAULT =====")

    while True:

        master_password = getpass.getpass(
            "Create master password: "
        )

        confirm_password = getpass.getpass(
            "Confirm master password: "
        )

        if master_password != confirm_password:
            print("Passwords do not match.")
            continue

        if len(master_password) < 12:
            print("Master password must contain at least 12 characters.")
            continue

        break

    salt = os.urandom(16)

    key = derive_key(master_password, salt)

    fernet = Fernet(
        base64.urlsafe_b64encode(key)
    )

    vault = {
        "credentials": []
    }

    encrypted_data = fernet.encrypt(
        json.dumps(vault).encode()
    )

    with open(VAULT_FILE, "wb") as file:

        file.write(salt)
        file.write(b"\n")
        file.write(encrypted_data)

    audit_log("New encrypted vault created.")

    print("\nSecure vault created successfully!")


def unlock_vault():

    if not os.path.exists(VAULT_FILE):
        create_new_vault()

    master_password = getpass.getpass(
        "\nEnter master password: "
    )

    try:

        with open(VAULT_FILE, "rb") as file:
            salt = file.readline().strip()
            encrypted_data = file.read()

        key = derive_key(master_password, salt)

        fernet = Fernet(
            base64.urlsafe_b64encode(key)
        )

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

        vault = json.loads(
            decrypted_data.decode()
        )

        audit_log("Successful vault unlock.")

        print("\nVault unlocked successfully!")

        return master_password, salt, vault

    except Exception:

        audit_log("Failed vault unlock attempt.")

        print("\nACCESS DENIED!")
        print("Incorrect master password.")

        return None, None, None


def save_vault(master_password, salt, vault):

    key = derive_key(master_password, salt)

    fernet = Fernet(
        base64.urlsafe_b64encode(key)
    )

    encrypted_data = fernet.encrypt(
        json.dumps(vault).encode()
    )

    with open(VAULT_FILE, "wb") as file:

        file.write(salt)
        file.write(b"\n")
        file.write(encrypted_data)


# ============================================================
# ADD PASSWORD
# ============================================================

def add_account(vault):

    print("\n===== ADD ACCOUNT =====")

    website = input("Website: ")
    username = input("Username: ")

    print("\n1. Enter password manually")
    print("2. Generate secure password")

    choice = input("Choose option: ")

    if choice == "2":

        try:
            length = int(
                input("Password length (minimum 12): ")
            )
        except ValueError:
            length = 20

        password = generate_password(length)

        print("\nGenerated password:")
        print(password)

    else:

        password = getpass.getpass(
            "Password: "
        )

    score, level, entropy, problems = check_password_strength(
        password
    )

    print("\n===== PASSWORD SECURITY =====")
    print(f"Security level : {level}")
    print(f"Security score : {score}/7")
    print(f"Entropy        : {entropy} bits")

    if problems:

        print("\nWarnings:")

        for problem in problems:
            print("-", problem)

    # Password reuse detection
    reused = False

    for account in vault["credentials"]:

        if account["password"] == password:

            reused = True

            print(
                "\nWARNING: This password is already used "
                "for another account."
            )

            break

    if reused:

        continue_anyway = input(
            "Save this reused password anyway? (y/n): "
        ).lower()

        if continue_anyway != "y":
            print("Account not saved.")
            return

    account = {
        "website": website,
        "username": username,
        "password": password
    }

    vault["credentials"].append(account)

    print("\nAccount added successfully.")

    audit_log(
        f"New credential added for {website}."
    )


# ============================================================
# VIEW ACCOUNTS
# ============================================================

def view_accounts(vault):

    print("\n===== SAVED ACCOUNTS =====")

    if not vault["credentials"]:

        print("No accounts saved.")

        return

    for number, account in enumerate(
        vault["credentials"],
        start=1
    ):

        print(f"\n{number}. {account['website']}")
        print(f"   Username: {account['username']}")
        print("   Password: ****")


# ============================================================
# RETRIEVE PASSWORD
# ============================================================

def retrieve_password(vault):

    print("\n===== RETRIEVE PASSWORD =====")

    if not vault["credentials"]:

        print("No accounts saved.")

        return

    for number, account in enumerate(
        vault["credentials"],
        start=1
    ):

        print(
            f"{number}. {account['website']}"
        )

    try:

        choice = int(
            input("\nSelect account number: ")
        )

        account = vault["credentials"][choice - 1]

        print("\nWebsite :", account["website"])
        print("Username:", account["username"])
        print("Password:", account["password"])

        audit_log(
            f"Password retrieved for {account['website']}."
        )

    except (ValueError, IndexError):

        print("Invalid selection.")


# ============================================================
# DELETE ACCOUNT
# ============================================================

def delete_account(vault):

    print("\n===== DELETE ACCOUNT =====")

    if not vault["credentials"]:

        print("No accounts saved.")

        return

    for number, account in enumerate(
        vault["credentials"],
        start=1
    ):

        print(
            f"{number}. {account['website']}"
        )

    try:

        choice = int(
            input("\nSelect account to delete: ")
        )

        account = vault["credentials"].pop(
            choice - 1
        )

        print(
            f"{account['website']} deleted."
        )

        audit_log(
            f"Credential deleted for {account['website']}."
        )

    except (ValueError, IndexError):

        print("Invalid selection.")


# ============================================================
# PASSWORD ANALYZER
# ============================================================

def analyze_password():

    print("\n===== PASSWORD SECURITY ANALYZER =====")

    password = getpass.getpass(
        "Enter password to analyze: "
    )

    score, level, entropy, problems = check_password_strength(
        password
    )

    print("\nSecurity Result")
    print("-------------------------")
    print(f"Level   : {level}")
    print(f"Score   : {score}/7")
    print(f"Entropy : {entropy} bits")

    if problems:

        print("\nRecommendations:")

        for problem in problems:
            print("-", problem)

    else:

        print(
            "\nNo major weaknesses detected."
        )


# ============================================================
# PASSWORD GENERATOR MENU
# ============================================================

def generator_menu():

    print("\n===== SECURE PASSWORD GENERATOR =====")

    try:

        length = int(
            input("Enter password length: ")
        )

    except ValueError:

        length = 20

    password = generate_password(length)

    print("\nGenerated password:")
    print(password)

    score, level, entropy, problems = check_password_strength(
        password
    )

    print("\nSecurity level:", level)
    print("Entropy:", entropy, "bits")


# ============================================================
# MAIN MENU
# ============================================================

def main():

    print("=" * 45)
    print("       CYBERSECURE PASSWORD MANAGER")
    print("=" * 45)

    master_password, salt, vault = unlock_vault()

    if vault is None:

        print("\nProgram terminated.")

        return

    while True:

        print("\n")
        print("========== SECURITY MENU ==========")
        print("1. Analyze password")
        print("2. Generate secure password")
        print("3. Add account")
        print("4. View saved accounts")
        print("5. Retrieve password")
        print("6. Delete account")
        print("7. Lock vault and exit")
        print("===================================")

        choice = input(
            "Enter your choice: "
        )

        if choice == "1":

            analyze_password()

        elif choice == "2":

            generator_menu()

        elif choice == "3":

            add_account(vault)

            save_vault(
                master_password,
                salt,
                vault
            )

        elif choice == "4":

            view_accounts(vault)

        elif choice == "5":

            retrieve_password(vault)

        elif choice == "6":

            delete_account(vault)

            save_vault(
                master_password,
                salt,
                vault
            )

        elif choice == "7":

            audit_log(
                "Vault locked and application closed."
            )

            print("\nVault locked.")
            print("Thank you for using CyberSecure Password Manager.")

            break

        else:

            print("Invalid choice. Please try again.")


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()