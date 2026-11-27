"""Makes one of the tap's two secrets in secrets/ (git-ignored): the log key or the card password.

    python tools/make_secret.py -h                               # this help
    python tools/make_secret.py log-key                          # a random log key, printed once
    python tools/make_secret.py card-password                    # a random password, printed once
    python tools/make_secret.py card-password --ask              # type your own (asked twice, hidden)
    python tools/make_secret.py log-key --dir D:/keys            # another folder (then cmake -DSECRETS_DIR=D:/keys)

Each is printed once; keep both. Both are compiled into the firmware, so rebuild and reflash after
making one. The log key goes in log_key.txt as it is, because the firmware seals and encrypts with
it. The card password goes in card_password_hash.txt only as its PBKDF2 hash, because the tap only
checks it; a new one replaces the old. A new card is accepted with a card_password.txt holding it in
its root.
"""
# Command line, the hidden prompt, the hash, paths, the random choices, and exiting with a message.
import argparse
import getpass
import hashlib
import os
import secrets
import sys

# The default secrets folder, beside tools/ in the repository, and the names of the two files in it.
SECRETS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "secrets"))
LOG_KEY_NAME = "log_key.txt"
CARD_PASSWORD_NAME = "card_password_hash.txt"
# The card password's hash cost, its longest length, and the characters a random one is made of.
ITERATIONS = 20000
MAX_BYTES = 64          # CARD_PASSWORD_MAX_BYTES
ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o, 1/l/i: read off a screen without doubt


def make_log_key(a):
    """Writes a new log key, unless one exists (logs made with it need it)."""
    path = os.path.join(a.dir, LOG_KEY_NAME)
    if os.path.exists(path):
        sys.exit(f"{path} already exists: not replaced (logs made with it need it)")
    key = secrets.token_hex(32)
    os.makedirs(a.dir, exist_ok=True)
    with open(path, "w") as f:
        f.write(key + "\n")
    print(f"wrote {path} (the build needs the key itself); rebuild and reflash the firmware to use it")
    print(f"the log key: {key}")
    print("keep it somewhere safe: without it no log can be read or verified")
    return 0


def trimmed(text):
    """The password as the tap reads it from card_password.txt: white space at either end dropped."""
    return text.strip(" \t\r\n")


def random_password():
    """Four groups of five characters: about 99 bits, e.g. kq7wd-3mxpa-..."""
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(5)) for _ in range(4))


def make_card_password(a):
    """Writes a new card password's hash, replacing any old one."""
    if a.ask:
        password = getpass.getpass("card password: ")
        if getpass.getpass("again: ") != password:
            sys.exit("the two did not match: nothing written")
    else:
        password = random_password()
    password = trimmed(password)
    raw = password.encode("utf-8")
    if not 1 <= len(raw) <= MAX_BYTES:
        sys.exit(f"a password is 1 to {MAX_BYTES} bytes once trimmed: nothing written")

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw, salt, ITERATIONS)
    path = os.path.join(a.dir, CARD_PASSWORD_NAME)
    os.makedirs(a.dir, exist_ok=True)
    with open(path, "w") as f:
        f.write(f"pbkdf2-sha256 {ITERATIONS} {salt.hex()} {digest.hex()}\n")
    print(f"wrote {path} (the hash only); rebuild and reflash the firmware to use it")
    if not a.ask:
        print(f"the card password: {password}")
        print("keep it somewhere safe: it is not stored anywhere, and a new card is accepted only with it")
    return 0


def main():
    """Makes the secret the command line names."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = argparse.ArgumentParser(add_help=False)
    where.add_argument("--dir", default=SECRETS, help=f"the secrets folder (default {SECRETS})")
    which = ap.add_subparsers(dest="secret", required=True, metavar="{log-key,card-password}")
    which.add_parser("log-key", parents=[where],
                     help="make log_key.txt (never replaced)").set_defaults(run=make_log_key)
    cp = which.add_parser("card-password", parents=[where], help="set the card password (card_password_hash.txt)")
    cp.add_argument("--ask", action="store_true", help="type the password (else a random one), not echoed")
    cp.set_defaults(run=make_card_password)
    a = ap.parse_args()
    return a.run(a)


if __name__ == "__main__":
    sys.exit(main())
