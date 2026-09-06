"""
Encrypt the READ-ONLY F5 service-account credentials used for data pull
(background cache pre-warm + cert-replace API discovery).

Usage:
    python scripts/encrypt_service_account.py
    python scripts/encrypt_service_account.py f5_service_account.enc

You'll be prompted for the service-account username and password.
The script writes an encrypted account file and prints the FERNET_KEY you must
set in the app's environment.

If FERNET_KEY is already in the environment, the script reuses it so
you can rotate the credentials without invalidating the key.
"""
import json
import getpass
import os
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Error: cryptography is not installed. Run: pip install cryptography")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
out_path = sys.argv[1].strip() if len(sys.argv) > 1 else os.getenv("F5_SERVICE_ACCOUNT_FILE", "").strip()
OUT = Path(out_path).resolve() if out_path else ROOT / "f5_service_account.enc"

print("F5 service-account encryptor")
print("=" * 40)

env_key = os.getenv("FERNET_KEY", "").strip()
if env_key:
    print("Using FERNET_KEY from environment.")
    key = env_key.encode()
else:
    answer = input("No FERNET_KEY in env. Generate a new one? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        key = Fernet.generate_key()
        print()
        print("Generated key (save this — needed to run the app):")
        print(f"  FERNET_KEY={key.decode()}")
        print()
        print("Add it to the service's environment (e.g. systemd unit or .env file).")
        print()
    else:
        key_input = getpass.getpass("Paste an existing FERNET_KEY: ").strip()
        if not key_input:
            print("No key supplied; aborting.")
            sys.exit(1)
        key = key_input.encode()

username = input("F5 service-account username: ").strip()
if not username:
    print("Username required; aborting.")
    sys.exit(1)
password = getpass.getpass("F5 service-account password: ")
if not password:
    print("Password required; aborting.")
    sys.exit(1)

try:
    f = Fernet(key)
except Exception as e:
    print(f"Invalid FERNET_KEY: {e}")
    sys.exit(1)

payload = json.dumps({"username": username, "password": password}).encode()
encrypted = f.encrypt(payload)
OUT.write_bytes(encrypted)
try:
    os.chmod(OUT, 0o600)
except Exception:
    pass

print()
print(f"Wrote encrypted credentials to: {OUT}")
print("Make sure FERNET_KEY is set in the app's environment before starting.")
