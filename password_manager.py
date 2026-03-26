"""
Password Storage App (Password Manager)
========================================
Part 2 of the Cybersecurity Project: Password Generator & Secure Storage App

CYBERSECURITY FEATURES IMPLEMENTED:
  1. Master-password hashing (SHA-256 + per-user salt via hashlib/secrets).
     Storing a plain-text master password would expose all stored credentials if
     the data file were ever read by an attacker. Hashing means only the *digest*
     is stored; we can verify a login attempt without ever saving the real password.

  2. Stored passwords are encrypted with Fernet symmetric encryption (from the
     `cryptography` library). Each password is encrypted before being saved and
     decrypted only when the authenticated user explicitly requests it.
     This prevents plain-text exposure in the JSON data file.

  3. The encryption key is derived from the master password using PBKDF2-HMAC-SHA256
     with 260,000 iterations and a random salt. This means the key is never stored
     directly; it is recreated at login time from the user's master password. An
     attacker who steals the data file still cannot decrypt the entries without the
     master password.

SECURITY NOTES:
  - This is an educational simulation. Production password managers use
    additional hardening (e.g., memory encryption, secure clipboard, audit logs).
  - The `cryptography` package must be installed: `pip install cryptography`

DATA FILE: passwords.json
  Stored structure (all values are base64 / hex strings — never plain text):
  {
    "users": {
      "<username>": {
        "password_hash": "<hex>",
        "hash_salt": "<hex>",
        "key_salt": "<hex>"
      }
    },
    "entries": {
      "<username>": {
        "<account_name>": "<encrypted_password_base64>"
      }
    }
  }
"""

import hashlib
import json
import os
import secrets

# ---------------------------------------------------------------------------
# Optional dependency: cryptography (Fernet encryption).
# If not installed, the app falls back to a clear warning and exits gracefully.
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwords.json")


# ---------------------------------------------------------------------------
# Data persistence helpers
# ---------------------------------------------------------------------------

def load_data() -> dict:
    """
    Load the JSON data file from disk.

    Returns
    -------
    dict – The parsed data, or a fresh empty structure if the file doesn't exist.
    """
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"users": {}, "entries": {}}


def save_data(data: dict) -> None:
    """
    Persist the data dictionary to the JSON file.

    Parameters
    ----------
    data : dict – The complete application data to save.
    """
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: bytes) -> str:
    """
    Hash a master password with SHA-256 and a random salt.

    Parameters
    ----------
    password : str   – The plain-text master password.
    salt     : bytes – A cryptographically random salt.

    Returns
    -------
    str – Hex-encoded SHA-256 digest.
    """
    digest = hashlib.sha256(salt + password.encode()).hexdigest()
    return digest


def derive_fernet_key(password: str, key_salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key from a master password using PBKDF2.

    Parameters
    ----------
    password : str   – The plain-text master password.
    key_salt : bytes – A cryptographically random salt (stored per user).

    Returns
    -------
    bytes – URL-safe base64-encoded 32-byte key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key_salt,
        # 260,000 iterations meets the OWASP recommended minimum for PBKDF2-HMAC-SHA256
        # (as of 2023), making brute-force attacks computationally expensive.
        iterations=260_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_password(plaintext: str, fernet: "Fernet") -> str:
    """
    Encrypt a plain-text password using Fernet symmetric encryption.

    Parameters
    ----------
    plaintext : str    – The password to encrypt.
    fernet    : Fernet – An initialised Fernet instance.

    Returns
    -------
    str – The encrypted token as a UTF-8 string.
    """
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_password(token: str, fernet: "Fernet") -> str:
    """
    Decrypt a Fernet-encrypted password token.

    Parameters
    ----------
    token  : str    – The encrypted token (UTF-8 string).
    fernet : Fernet – An initialised Fernet instance.

    Returns
    -------
    str – The original plain-text password.
    """
    return fernet.decrypt(token.encode()).decode()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def register_user(data: dict, username: str, master_password: str) -> bool:
    """
    Register a new user with a hashed master password and key derivation salt.

    Parameters
    ----------
    data            : dict – The application data dictionary (mutated in place).
    username        : str  – Desired username.
    master_password : str  – Chosen master password (plain text).

    Returns
    -------
    bool – True if registration succeeded, False if username already exists.
    """
    if username in data["users"]:
        return False  # Username taken

    hash_salt = secrets.token_bytes(32)   # Salt for password hashing
    key_salt  = secrets.token_bytes(32)   # Salt for key derivation

    data["users"][username] = {
        "password_hash": hash_password(master_password, hash_salt),
        "hash_salt":     hash_salt.hex(),
        "key_salt":      key_salt.hex(),
    }
    data["entries"][username] = {}
    save_data(data)
    return True


def verify_login(data: dict, username: str, master_password: str) -> bool:
    """
    Verify a login attempt against the stored password hash.

    Parameters
    ----------
    data            : dict – The application data dictionary.
    username        : str  – Username to authenticate.
    master_password : str  – Supplied master password (plain text).

    Returns
    -------
    bool – True if credentials are correct, False otherwise.
    """
    if username not in data["users"]:
        return False

    user = data["users"][username]
    hash_salt = bytes.fromhex(user["hash_salt"])
    expected  = user["password_hash"]
    actual    = hash_password(master_password, hash_salt)
    return secrets.compare_digest(actual, expected)  # Constant-time comparison


# ---------------------------------------------------------------------------
# Password manager operations
# ---------------------------------------------------------------------------

def add_entry(data: dict, username: str, account: str,
              password: str, fernet: "Fernet") -> None:
    """
    Add or update an encrypted password entry for the given account.

    Parameters
    ----------
    data     : dict   – The application data dictionary (mutated in place).
    username : str    – Authenticated username.
    account  : str    – Account/service name (e.g. 'gmail'). Stored in lowercase
                        so entries are case-insensitive (e.g. 'Gmail' == 'gmail').
    password : str    – Plain-text password to store (will be encrypted).
    fernet   : Fernet – Fernet instance for encryption.
    """
    data["entries"][username][account.lower()] = encrypt_password(password, fernet)
    save_data(data)


def retrieve_entry(data: dict, username: str, account: str,
                   fernet: "Fernet") -> str | None:
    """
    Retrieve and decrypt a stored password for the given account.

    Parameters
    ----------
    data     : dict   – The application data dictionary.
    username : str    – Authenticated username.
    account  : str    – Account/service name to look up.
    fernet   : Fernet – Fernet instance for decryption.

    Returns
    -------
    str | None – The plain-text password, or None if the account isn't found.
    """
    entries = data["entries"].get(username, {})
    token = entries.get(account.lower())
    if token is None:
        return None
    return decrypt_password(token, fernet)


def list_accounts(data: dict, username: str) -> list:
    """
    Return a list of stored account names (no passwords) for the given user.

    Parameters
    ----------
    data     : dict – The application data dictionary.
    username : str  – Authenticated username.

    Returns
    -------
    list – Sorted list of account name strings.
    """
    return sorted(data["entries"].get(username, {}).keys())


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def print_menu():
    print()
    print("  ┌─────────────────────────────┐")
    print("  │   Password Manager Menu     │")
    print("  ├─────────────────────────────┤")
    print("  │  1. Add a password          │")
    print("  │  2. Retrieve a password     │")
    print("  │  3. View stored accounts    │")
    print("  │  4. Log out                 │")
    print("  └─────────────────────────────┘")


def main():
    if not CRYPTO_AVAILABLE:
        print("[ERROR] The 'cryptography' package is required but not installed.")
        print("        Run:  pip install cryptography")
        return

    print("=" * 50)
    print("   Password Storage App")
    print("=" * 50)

    data = load_data()

    # ---- Outer loop: authentication ----------------------------------------
    while True:
        print()
        print("  1. Log in")
        print("  2. Register new account")
        print("  3. Quit")
        choice = input("\nSelect option: ").strip()

        if choice == "3":
            print("Goodbye!")
            break

        elif choice == "2":
            # Registration
            username = input("Choose a username: ").strip()
            if not username:
                print("  [!] Username cannot be empty.")
                continue
            master_pw = input("Choose a master password: ").strip()
            if len(master_pw) < 8:
                print("  [!] Master password must be at least 8 characters.")
                continue
            if register_user(data, username, master_pw):
                print(f"  [✓] Account '{username}' created successfully.")
            else:
                print(f"  [!] Username '{username}' is already taken.")

        elif choice == "1":
            # Login
            username = input("Username: ").strip()
            master_pw = input("Master password: ").strip()

            if not verify_login(data, username, master_pw):
                print("  [!] Invalid username or password.")
                continue

            print(f"\n  [✓] Welcome, {username}!")

            # Derive encryption key from master password (never stored directly)
            key_salt = bytes.fromhex(data["users"][username]["key_salt"])
            fernet_key = derive_fernet_key(master_pw, key_salt)
            fernet = Fernet(fernet_key)

            # ---- Inner loop: password manager menu -------------------------
            while True:
                print_menu()
                action = input("\nSelect option: ").strip()

                if action == "1":
                    # Add a password
                    account = input("  Account name (e.g. gmail): ").strip()
                    if not account:
                        print("  [!] Account name cannot be empty.")
                        continue
                    password = input(f"  Password for '{account}': ").strip()
                    if not password:
                        print("  [!] Password cannot be empty.")
                        continue
                    add_entry(data, username, account, password, fernet)
                    print(f"  [✓] Password for '{account}' saved (encrypted).")

                elif action == "2":
                    # Retrieve a password
                    account = input("  Account name to retrieve: ").strip()
                    result = retrieve_entry(data, username, account, fernet)
                    if result is None:
                        print(f"  [!] No entry found for '{account}'.")
                    else:
                        print(f"  [✓] Password for '{account}': {result}")

                elif action == "3":
                    # View stored account names (not passwords)
                    accounts = list_accounts(data, username)
                    if accounts:
                        print("\n  Stored accounts:")
                        for acc in accounts:
                            print(f"    • {acc}")
                    else:
                        print("  [i] No passwords stored yet.")

                elif action == "4":
                    # Log out
                    print(f"\n  Logged out. Goodbye, {username}!")
                    break

                else:
                    print("  [!] Invalid option. Please choose 1–4.")

        else:
            print("  [!] Invalid option. Please choose 1–3.")


if __name__ == "__main__":
    main()
