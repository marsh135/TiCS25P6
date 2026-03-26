"""
Secure Password Generator
=========================
Part 1 of the Cybersecurity Project: Password Generator & Secure Storage App

WHY RANDOMNESS MATTERS:
  Predictable passwords (e.g., "password123", "abc123") are trivial to crack with
  dictionary attacks or brute-force tools. True randomness means an attacker
  cannot guess the next character based on previous ones. Python's `secrets`
  module draws from the OS cryptographic random-number generator (CSPRNG),
  which is suitable for security-sensitive work—unlike `random`, which is only
  pseudo-random and NOT safe for cryptography.

WHAT MAKES A PASSWORD "STRONG":
  1. Length: The longer the password, the larger the search space for attackers.
     A 12-character password is exponentially harder to crack than an 8-character one.
  2. Character variety: Mixing uppercase, lowercase, digits, and symbols dramatically
     increases the number of possible combinations.
  3. Unpredictability: Avoid dictionary words, names, dates, or repeating patterns.
  4. Uniqueness: Every account should have its own distinct password.
"""

import secrets
import string


# ---------------------------------------------------------------------------
# Character pools
# ---------------------------------------------------------------------------
UPPERCASE = string.ascii_uppercase          # A-Z
LOWERCASE = string.ascii_lowercase          # a-z
DIGITS    = string.digits                   # 0-9
SYMBOLS   = string.punctuation             # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

# Characters that look alike and can cause confusion when reading/typing
CONFUSING = set("0O1lI|")


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_confusing: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Parameters
    ----------
    length          : int   – Desired password length (minimum 4).
    use_upper       : bool  – Include uppercase letters (A-Z).
    use_lower       : bool  – Include lowercase letters (a-z).
    use_digits      : bool  – Include digits (0-9).
    use_symbols     : bool  – Include special/symbol characters.
    exclude_confusing: bool – Remove visually ambiguous characters (0, O, 1, l, I, |).

    Returns
    -------
    str – The generated password.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    # Build the pool of allowed characters
    pool = ""
    required = []  # Guarantee at least one character of each chosen type

    if use_upper:
        chars = UPPERCASE
        if exclude_confusing:
            chars = "".join(c for c in chars if c not in CONFUSING)
        pool += chars
        required.append(secrets.choice(chars))

    if use_lower:
        chars = LOWERCASE
        if exclude_confusing:
            chars = "".join(c for c in chars if c not in CONFUSING)
        pool += chars
        required.append(secrets.choice(chars))

    if use_digits:
        chars = DIGITS
        if exclude_confusing:
            chars = "".join(c for c in chars if c not in CONFUSING)
        pool += chars
        required.append(secrets.choice(chars))

    if use_symbols:
        chars = SYMBOLS
        if exclude_confusing:
            chars = "".join(c for c in chars if c not in CONFUSING)
        pool += chars
        required.append(secrets.choice(chars))

    if not pool:
        raise ValueError("At least one character type must be selected.")

    # Fill the rest of the password randomly from the full pool
    remaining_length = length - len(required)
    rest = [secrets.choice(pool) for _ in range(remaining_length)]

    # Combine required characters with the rest and shuffle
    password_list = required + rest
    secrets.SystemRandom().shuffle(password_list)

    return "".join(password_list)


def rate_strength(password: str) -> str:
    """
    Rate the strength of a password as 'Weak', 'Medium', or 'Strong'.

    Parameters
    ----------
    password : str – The password to evaluate.

    Returns
    -------
    str – A strength label: 'Weak', 'Medium', or 'Strong'.
    """
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if any(c in UPPERCASE for c in password):
        score += 1
    if any(c in LOWERCASE for c in password):
        score += 1
    if any(c in DIGITS for c in password):
        score += 1
    if any(c in SYMBOLS for c in password):
        score += 1

    if score <= 3:
        return "Weak"
    elif score <= 5:
        return "Medium"
    else:
        return "Strong"


def get_yes_no(prompt: str) -> bool:
    """Ask the user a yes/no question and return True for yes, False for no."""
    while True:
        answer = input(prompt + " (y/n): ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")


def get_int(prompt: str, min_val: int, max_val: int) -> int:
    """Prompt the user for an integer within [min_val, max_val]."""
    while True:
        try:
            value = int(input(prompt).strip())
            if min_val <= value <= max_val:
                return value
            print(f"  Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("  Invalid input. Please enter a whole number.")


def main():
    print("=" * 50)
    print("   Secure Password Generator")
    print("=" * 50)

    while True:
        print()
        # --- Collect user preferences ---
        length = get_int("Password length (4–128): ", 4, 128)
        use_upper   = get_yes_no("Include uppercase letters (A-Z)?")
        use_lower   = get_yes_no("Include lowercase letters (a-z)?")
        use_digits  = get_yes_no("Include numbers (0-9)?")
        use_symbols = get_yes_no("Include symbols (!@#...)?")
        exclude_confusing = get_yes_no("Exclude confusing characters (0, O, 1, l, I)?")

        # At least one type must be selected
        if not any([use_upper, use_lower, use_digits, use_symbols]):
            print("\n  [!] You must select at least one character type. Try again.")
            continue

        # --- Generate and display the password ---
        password = generate_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_confusing=exclude_confusing,
        )
        strength = rate_strength(password)

        print()
        print(f"  Generated Password : {password}")
        print(f"  Strength Rating    : {strength}")

        # --- Ask to generate another ---
        again = get_yes_no("\nGenerate another password?")
        if not again:
            print("\nGoodbye! Stay secure.")
            break


if __name__ == "__main__":
    main()
