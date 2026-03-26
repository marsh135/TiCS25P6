# TiCS25P6 – Password Generator & Secure Storage App

A cybersecurity project that builds two command-line tools:

1. **`password_generator.py`** – Generates cryptographically secure random passwords
2. **`password_manager.py`** – A password storage app with login, encryption, and a menu interface

---

## Project Description

This project demonstrates core cybersecurity concepts through hands-on Python development:

- **Randomness & entropy** – why unpredictable passwords resist brute-force attacks
- **Password hashing** – storing only the hash of a master password, never the plain text
- **Symmetric encryption** – encrypting each stored password with a key derived from the master password
- **Key derivation** – using PBKDF2-HMAC-SHA256 to turn a human-chosen password into a strong cryptographic key

---

## How to Run the Programs

### Prerequisites

```bash
pip install cryptography
```

> `cryptography` is required only by `password_manager.py`.
> `password_generator.py` uses the Python standard library only.

### Part 1 – Password Generator

```bash
python password_generator.py
```

You will be prompted to choose:
- Password length (4–128 characters)
- Whether to include uppercase, lowercase, digits, and/or symbols
- Whether to exclude visually confusing characters (e.g. `0`, `O`, `1`, `l`)

The program prints the generated password and a strength rating (Weak / Medium / Strong).

### Part 2 – Password Manager

```bash
python password_manager.py
```

On first run, choose **Register new account** to create a username and master password.
After logging in, the menu lets you:

| Option | Action |
|--------|--------|
| 1 | Add a password for an account |
| 2 | Retrieve (decrypt) a stored password |
| 3 | View a list of stored account names (no passwords shown) |
| 4 | Log out |

Stored data is saved to **`passwords.json`** in the same directory.

---

## Security Features Implemented

### Password Generator (`password_generator.py`)

| Feature | Details |
|---------|---------|
| Cryptographic RNG | Uses Python's `secrets` module (backed by the OS CSPRNG) instead of `random` |
| Guaranteed character variety | At least one character of each selected type is always included |
| Shuffle after assembly | Avoids predictable positions (e.g. first character always uppercase) |
| Strength rater | Evaluates length and character diversity to label a password Weak / Medium / Strong |
| Confusing-character exclusion | Optional removal of `0 O 1 l I |` to avoid transcription errors |

**Why randomness matters:**  
Predictable patterns (keyboard walks, dictionary words, birth years) can be cracked in seconds. A CSPRNG ensures each character is statistically independent, making guessing computationally infeasible at sufficient length.

**What makes a password strong:**
- Length ≥ 16 characters
- Mix of uppercase, lowercase, digits, and symbols
- No dictionary words or repeated patterns
- Unique per account

---

### Password Manager (`password_manager.py`)

| Feature | Details |
|---------|---------|
| Master password hashing | SHA-256 with a per-user random salt (32 bytes) – the plain-text password is never stored |
| Constant-time comparison | `secrets.compare_digest` prevents timing-based side-channel attacks during login |
| Fernet symmetric encryption | Every stored password is encrypted before being written to disk |
| PBKDF2 key derivation | The encryption key is derived from the master password using 260,000 iterations of PBKDF2-HMAC-SHA256 – a separate random salt per user means an attacker who steals the file cannot decrypt entries without the master password |
| No plain-text exposure | `passwords.json` contains only hex salts, a SHA-256 hash, and base64-encoded Fernet tokens |

---

## What I Would Improve with More Time

- **Argon2 / bcrypt hashing** – More resistant to GPU-accelerated cracking than SHA-256
- **Multiple user accounts** – Already supported; could add an admin role and per-account access controls
- **Clipboard integration** – Copy passwords directly to clipboard without printing them to the terminal
- **Auto-generate passwords** – Let the manager call the generator when adding a new entry
- **Password breach checker** – Query the Have I Been Pwned API (k-anonymity model) to warn about compromised passwords
- **File encryption at rest** – Encrypt the entire `passwords.json` file, not just individual entries
- **GUI (Tkinter)** – A graphical interface for easier use
- **Audit log** – Record login attempts and access events for accountability
- **Session timeout** – Automatically log out after a period of inactivity

---

## Grading Checklist

- [x] Password generator works (generates secure, random passwords)
- [x] Storage system works (add, retrieve, list)
- [x] Authentication works (register + login with hashed master password)
- [x] Demonstrates secure thinking (hashing, encryption, key derivation)
- [x] Explains security choices in README
- [x] Uses dictionary / list for data storage
- [x] Has user-defined functions with parameters and return values
- [x] Uses selection (`if/else`) and iteration (loops)
- [x] README included
