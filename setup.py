#!/usr/bin/env python3
"""
setup.py — First-time setup for Secure Contact Book v2
Run this once before starting app.py
"""

import json, os, sys
from crypto_util import load_or_create_key, hash_password

KEY_FILE   = "key.key"
USER_DB    = "user_db.json"
CONTACT_DB = "contact_db.json"
AUDIT_LOG  = "audit_log.json"

def main():
    print("\n╔══════════════════════════════════════════╗")
    print("║  Secure Contact Book v2 — Setup Wizard  ║")
    print("╚══════════════════════════════════════════╝\n")

    # 1. Encryption key
    if os.path.exists(KEY_FILE):
        print(f"[✓] Encryption key found: {KEY_FILE}")
    else:
        load_or_create_key(KEY_FILE)
        print(f"[✓] New encryption key generated: {KEY_FILE}")
        print(f"    ⚠  BACK UP THIS FILE. Losing it means losing all contacts.")

    # 2. User database
    if os.path.exists(USER_DB):
        with open(USER_DB) as f:
            users = json.load(f)
        print(f"[✓] User database found with {len(users)} user(s): {', '.join(users.keys())}")
    else:
        print("\nNo user database found. Creating admin account…")
        username = input("  Admin username [admin]: ").strip() or "admin"
        import getpass
        while True:
            pw  = getpass.getpass("  Admin password (min 8 chars): ")
            pw2 = getpass.getpass("  Confirm password: ")
            if pw != pw2:
                print("  ✗ Passwords do not match, try again.")
            elif len(pw) < 8:
                print("  ✗ Password too short.")
            else:
                break
        from datetime import datetime, timezone
        users = {
            username: {
                "username": username,
                "password": hash_password(pw),
                "role":     "admin",
                "created":  datetime.now(timezone.utc).isoformat(),
            }
        }
        with open(USER_DB, "w") as f:
            json.dump(users, f, indent=2)
        print(f"  [✓] Admin user '{username}' created.")

    # 3. Contact database
    if not os.path.exists(CONTACT_DB):
        with open(CONTACT_DB, "w") as f:
            json.dump([], f)
        print(f"[✓] Empty contact database created: {CONTACT_DB}")
    else:
        with open(CONTACT_DB) as f:
            contacts = json.load(f)
        print(f"[✓] Contact database found: {len(contacts)} contact(s)")

        # Migrate old format (list of {name, phone} strings)
        migrated = 0
        import uuid
        from datetime import datetime, timezone
        for c in contacts:
            if "id" not in c:
                c["id"]      = str(uuid.uuid4())
                c["email"]   = ""
                c["address"] = ""
                c["company"] = ""
                c["notes"]   = ""
                c["tags"]    = []
                c["favorite"]= False
                c["created"] = datetime.now(timezone.utc).isoformat()
                c["updated"] = datetime.now(timezone.utc).isoformat()
                migrated += 1
        if migrated:
            with open(CONTACT_DB, "w") as f:
                json.dump(contacts, f, indent=2)
            print(f"  [✓] Migrated {migrated} legacy contact(s) to v2 schema.")

    # 4. Audit log
    if not os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, "w") as f:
            json.dump([], f)
        print(f"[✓] Audit log created: {AUDIT_LOG}")

    print("\n✅ Setup complete! Run:  python app.py")
    print("   Then open http://localhost:5000 in your browser.\n")

if __name__ == "__main__":
    # Must run from the project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    main()
