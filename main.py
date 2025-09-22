#!/usr/bin/env python3 
"""
Password Vault - Multi-user secure local password manager
"""

import sqlite3
import hashlib
import secrets
import base64
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass


class PasswordVault:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self.conn = None
        self.cipher = None
        self.user_id = None  # track logged-in user

    def initialize_db(self):
        """Initialize database with required tables and upgrade schema if needed"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()

        # --- Create users table ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL,
            key_hash BLOB NOT NULL
            )
        ''')

        # --- Create passwords table (basic structure) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
            )
        ''')
        self.conn.commit()

        # --- Schema upgrade check ---
        cursor.execute("PRAGMA table_info(passwords)")
        columns = [col[1] for col in cursor.fetchall()]

        # List of expected columns (for migration)
        expected_columns = {
            "user_id": "INTEGER",
            "notes": "TEXT",
            "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        }

        for col, col_type in expected_columns.items():
            if col not in columns:
                cursor.execute(f"ALTER TABLE passwords ADD COLUMN {col} {col_type}")
                print(f"[DB Upgrade] Added missing column: {col}")

        # Ensure UNIQUE constraint with user_id
        # (SQLite can't alter constraints directly, so we skip auto-fix here)
        self.conn.commit()

    def derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup_vault(self, username, master_password):
        """Create a new vault for a user"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False  # user already exists

        salt = secrets.token_bytes(16)
        key = self.derive_key(master_password, salt)
        key_hash = hashlib.sha256((master_password + salt.hex()).encode()).digest()

        cursor.execute(
            "INSERT INTO users (username, salt, key_hash) VALUES (?, ?, ?)",
            (username, salt, key_hash)
        )
        self.conn.commit()

        self.user_id = cursor.lastrowid
        self.cipher = Fernet(key)
        return True

    def unlock_vault(self, username, master_password):
        """Unlock an existing vault"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, salt, key_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            return False

        user_id, salt, stored_hash = result
        test_hash = hashlib.sha256((master_password + salt.hex()).encode()).digest()
        if test_hash != stored_hash:
            return False

        key = self.derive_key(master_password, salt)
        self.user_id = user_id
        self.cipher = Fernet(key)
        return True

    def change_master_password(self, old_password, new_password, confirm_password):
        """Change the master password for the current user"""
        if not self.user_id:
            return False

        cursor = self.conn.cursor()
        cursor.execute("SELECT salt, key_hash FROM users WHERE id=?", (self.user_id,))
        result = cursor.fetchone()
        if not result:
            return False

        old_salt, stored_hash = result
        test_hash = hashlib.sha256((old_password + old_salt.hex()).encode()).digest()
        if test_hash != stored_hash:
            return False  # old password incorrect

        # Generate new salt + key
        new_salt = secrets.token_bytes(16)
        new_key = self.derive_key(new_password, new_salt)
        new_hash = hashlib.sha256((new_password + new_salt.hex()).encode()).digest()

        cursor.execute(
            "UPDATE users SET salt=?, key_hash=? WHERE id=?",
            (new_salt, new_hash, self.user_id)
        )
        self.conn.commit()

        # Update current session cipher
        self.cipher = Fernet(new_key)
        return True

    def add_password(self, service, username, password, notes=""):
        """Add a new password entry for the logged-in user"""
        if not self.user_id:
            return False
        cursor = self.conn.cursor()
        enc_pwd = self.cipher.encrypt(password.encode())
        cursor.execute(
            "INSERT INTO passwords (user_id, service, username, password, notes) VALUES (?, ?, ?, ?, ?)",
            (self.user_id, service, username, enc_pwd, notes)
        )
        self.conn.commit()
        return True

    def get_password(self, service, username):
        """Retrieve a password"""
        if not self.cipher or not self.user_id:
            return None

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT password FROM passwords WHERE user_id=? AND service=? AND username=?",
            (self.user_id, service, username)
        )
        result = cursor.fetchone()
        if result:
            return self.cipher.decrypt(result[0]).decode()
        return None

    def get_entry(self, service, username):
        """Retrieve full entry details (decrypt password too)"""
        if not self.user_id:
            return None
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT username, password, notes FROM passwords WHERE user_id=? AND service=? AND username=?",
            (self.user_id, service, username)
        )
        row = cursor.fetchone()
        if row:
            dec_pwd = self.cipher.decrypt(row[1]).decode()
            return {"username": row[0], "password": dec_pwd, "notes": row[2]}
        return None

    def delete_entry(self, service, username):
        """Delete an entry for a service + username"""
        if not self.user_id:
            return False
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM passwords WHERE user_id=? AND service=? AND username=?",
            (self.user_id, service, username)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def list_services(self):
        if not self.user_id:
            return []
        cursor = self.conn.cursor()
        cursor.execute(
        "SELECT DISTINCT service FROM passwords WHERE user_id=?",
        (self.user_id,)
    )
        return [row[0] for row in cursor.fetchall()]



    def list_entries(self, service):
        """List all usernames for a given service"""
        if not self.user_id:
            return []
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT username FROM passwords WHERE user_id=? AND service=?",
            (self.user_id, service)
        )
        return [row[0] for row in cursor.fetchall()]

    def generate_password(self, length=16):
        """Generate random secure password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def close(self):
        if self.conn:
            self.conn.close()


def display_entry(entry):
    """Pretty-print entry"""
    print(f"\nService: {entry['service']}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")
    if entry['notes']:
        print(f"Notes: {entry['notes']}")
    print(f"Created: {entry['created_at']}")
    print(f"Updated: {entry['updated_at']}")


def main():
    vault = PasswordVault()
    vault.initialize_db()

    print("=== Password Vault ===")
    print("1. Create new vault")
    print("2. Unlock existing vault")
    choice = input("Choose option (1/2): ")

    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty!")
        return

    if choice == "1":
        password = getpass("Create master password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters!")
            return

        confirm = getpass("Confirm master password: ")
        if password != confirm:
            print("Passwords do not match!")
            return

        if vault.setup_vault(username, password):
            print("Vault created successfully!")
        else:
            print("Username already exists!")
            return

    elif choice == "2":
        password = getpass("Enter master password: ")
        if not vault.unlock_vault(username, password):
            print("Invalid username or password!")
            return
        print("Vault unlocked successfully!")

    else:
        print("Invalid choice!")
        return

    # Main loop
    while True:
        print("\n=== Main Menu ===")
        print("1. Add password")
        print("2. Retrieve password")
        print("3. List services")
        print("4. View entry details")
        print("5. Delete entry")
        print("6. Generate password")
        print("7. Change master password")
        print("8. Exit")

        choice = input("Choose option (1-8): ")

        if choice == "1":
            service = input("Service: ")
            uname = input("Username: ")
            pwd = getpass("Password (leave empty to generate): ")

            if not pwd:
                pwd = vault.generate_password()
                print(f"Generated password: {pwd}")

            notes = input("Notes (optional): ") or None
            if vault.add_password(service, uname, pwd, notes):
                print("Password saved successfully!")
            else:
                print("Failed to save password!")

        elif choice == "2":
            service = input("Service: ")
            usernames = vault.list_entries(service)
            if not usernames:
                print("No entries found for this service!")
                continue

            print("Usernames:")
            for i, uname in enumerate(usernames, 1):
                print(f"{i}. {uname}")

            try:
                sel = int(input("Select username number: "))
                uname = usernames[sel - 1]
                pwd = vault.get_password(service, uname)
                print(f"Password: {pwd}")

                copy = input("Copy to clipboard? (y/N): ")
                if copy.lower() == "y":
                    pyperclip.copy(pwd)
                    print("Password copied to clipboard!")
            except (ValueError, IndexError):
                print("Invalid selection!")

        elif choice == "3":
            services = vault.list_services()
            if services:
                print("Services:")
                for service in services:
                    count = len(vault.list_entries(service))
                    print(f"- {service} ({count} entries)")
            else:
                print("No services found!")

        elif choice == "4":
            service = input("Service: ")
            usernames = vault.list_entries(service)
            if not usernames:
                print("No entries found for this service!")
                continue

            print("Usernames:")
            for i, uname in enumerate(usernames, 1):
                print(f"{i}. {uname}")

            try:
                sel = int(input("Select username number: "))
                uname = usernames[sel - 1]
                entry = vault.get_entry(service, uname)
                if entry:
                    display_entry(entry)
                else:
                    print("Entry not found!")
            except (ValueError, IndexError):
                print("Invalid selection!")

        elif choice == "5":
            service = input("Service: ")
            usernames = vault.list_entries(service)
            if not usernames:
                print("No entries found for this service!")
                continue

            print("Usernames:")
            for i, uname in enumerate(usernames, 1):
                print(f"{i}. {uname}")

            try:
                sel = int(input("Select username number to delete: "))
                uname = usernames[sel - 1]
                confirm = input(f"Are you sure you want to delete {service}/{uname}? (y/N): ")
                if confirm.lower() == "y":
                    if vault.delete_entry(service, uname):
                        print("Entry deleted successfully!")
                    else:
                        print("Failed to delete entry!")
            except (ValueError, IndexError):
                print("Invalid selection!")

        elif choice == "6":
            try:
                length = int(input("Password length (default 16): ") or "16")
                pwd = vault.generate_password(length)
                print(f"Generated password: {pwd}")

                copy = input("Copy to clipboard? (y/N): ")
                if copy.lower() == "y":
                    pyperclip.copy(pwd)
                    print("Password copied to clipboard!")
            except ValueError:
                print("Invalid length!")

        elif choice == "7":
            old_pwd = getpass("Enter current master password: ")
            new_pwd = getpass("Enter new master password: ")
            confirm = getpass("Confirm new master password: ")

            if new_pwd != confirm:
                print("New passwords do not match!")
            elif len(new_pwd) < 8:
                print("New password must be at least 8 characters!")
            elif vault.change_master_password(old_pwd, new_pwd):
                print("Master password changed successfully!")
            else:
                print("Failed to change master password!")

        elif choice == "8":
            print("Goodbye!")
            break

        else:
            print("Invalid choice!")

    vault.close()


if __name__ == "__main__":
    main()
