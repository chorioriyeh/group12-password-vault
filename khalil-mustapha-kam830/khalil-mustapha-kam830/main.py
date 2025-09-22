# !/usr/bin/env python3
# """
# Password Vault - A secure local password manager
# """
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
        
    def initialize_db(self):
        """Initialize database with required tables"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                key_hash BLOB NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(service, username)
            )
        ''')
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
    
    def setup_vault(self, master_password):
        """Set up a new password vault"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM master")
        if cursor.fetchone():
            return False
        
        salt = secrets.token_bytes(16)
        key = self.derive_key(master_password, salt)
        key_hash = hashlib.sha256((master_password + salt.hex()).encode()).digest()
        
        cursor.execute("INSERT INTO master (salt, key_hash) VALUES (?, ?)", (salt, key_hash))
        self.conn.commit()
        
        self.cipher = Fernet(key)
        return True
    
    def unlock_vault(self, master_password):
        """Unlock existing vault"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT salt, key_hash FROM master")
        result = cursor.fetchone()
        if not result:
            return False
        
        salt, stored_hash = result
        test_hash = hashlib.sha256((master_password + salt.hex()).encode()).digest()
        if test_hash != stored_hash:
            return False
        
        key = self.derive_key(master_password, salt)
        self.cipher = Fernet(key)
        return True
    
    def add_password(self, service, username, password, notes=None):
        """Add a new password entry"""
        if not self.cipher:
            return False
        
        encrypted_password = self.cipher.encrypt(password.encode())
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO passwords (service, username, password, notes) VALUES (?, ?, ?, ?)",
                (service, username, encrypted_password, notes)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Entry already exists, update it instead
            cursor.execute(
                "UPDATE passwords SET password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE service = ? AND username = ?",
                (encrypted_password, notes, service, username)
            )
            self.conn.commit()
            return True
    
    def get_password(self, service, username):
        """Retrieve a password"""
        if not self.cipher:
            return None
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT password FROM passwords WHERE service = ? AND username = ?",
            (service, username)
        )
        result = cursor.fetchone()
        if result:
            return self.cipher.decrypt(result[0]).decode()
        return None
    
    def get_entry(self, service, username):
        """Get complete entry details"""
        if not self.cipher:
            return None
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT service, username, password, notes, created_at, updated_at FROM passwords WHERE service = ? AND username = ?",
            (service, username)
        )
        result = cursor.fetchone()
        if result:
            service, username, encrypted_password, notes, created_at, updated_at = result
            return {
                'service': service,
                'username': username,
                'password': self.cipher.decrypt(encrypted_password).decode(),
                'notes': notes,
                'created_at': created_at,
                'updated_at': updated_at
            }
        return None
    
    def delete_entry(self, service, username):
        """Delete a password entry"""
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM passwords WHERE service = ? AND username = ?",
            (service, username)
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def list_services(self):
        """List all services"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT service FROM passwords ORDER BY service")
        return [row[0] for row in cursor.fetchall()]
    
    def list_entries(self, service):
        """List all entries for a service"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT username FROM passwords WHERE service = ? ORDER BY username",
            (service,)
        )
        return [row[0] for row in cursor.fetchall()]
    
    def generate_password(self, length=16):
        """Generate a strong random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def change_master_password(self, old_password, new_password):
        """Change the master password and re-encrypt all data"""
        if not self.unlock_vault(old_password):
            return False
        
        # Get all entries
        cursor = self.conn.cursor()
        cursor.execute("SELECT service, username, password, notes FROM passwords")
        entries = cursor.fetchall()
        
        # Decrypt all entries with old key
        decrypted_entries = []
        for service, username, encrypted_password, notes in entries:
            password = self.cipher.decrypt(encrypted_password).decode()
            decrypted_entries.append((service, username, password, notes))
        
        # Create new master key
        new_salt = secrets.token_bytes(16)
        new_key = self.derive_key(new_password, new_salt)
        new_key_hash = hashlib.sha256((new_password + new_salt.hex()).encode()).digest()
        
        # Update master table
        cursor.execute("UPDATE master SET salt = ?, key_hash = ?", (new_salt, new_key_hash))
        
        # Re-encrypt all entries with new key
        self.cipher = Fernet(new_key)
        for service, username, password, notes in decrypted_entries:
            encrypted_password = self.cipher.encrypt(password.encode())
            cursor.execute(
                "UPDATE passwords SET password = ? WHERE service = ? AND username = ?",
                (encrypted_password, service, username)
            )
        
        self.conn.commit()
        return True
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

def display_entry(entry):
    """Display entry details in a formatted way"""
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
    
    if choice == "1":
        password = getpass("Create master password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters!")
            return
        
        confirm = getpass("Confirm master password: ")
        if password != confirm:
            print("Passwords do not match!")
            return
            
        if vault.setup_vault(password):
            print("Vault created successfully!")
        else:
            print("Vault already exists!")
            return
    elif choice == "2":
        password = getpass("Enter master password: ")
        if not vault.unlock_vault(password):
            print("Invalid password!")
            return
        print("Vault unlocked successfully!")
    else:
        print("Invalid choice!")
        return
    
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
            username = input("Username: ")
            password = getpass("Password (leave empty to generate): ")
            
            if not password:
                password = vault.generate_password()
                print(f"Generated password: {password}")
            
            notes = input("Notes (optional): ") or None
            if vault.add_password(service, username, password, notes):
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
            for i, username in enumerate(usernames, 1):
                print(f"{i}. {username}")
            
            try:
                choice = int(input("Select username number: "))
                username = usernames[choice - 1]
                password = vault.get_password(service, username)
                print(f"Password: {password}")
                
                copy = input("Copy to clipboard? (y/N): ")
                if copy.lower() == 'y':
                    pyperclip.copy(password)
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
            for i, username in enumerate(usernames, 1):
                print(f"{i}. {username}")
            
            try:
                choice = int(input("Select username number: "))
                username = usernames[choice - 1]
                entry = vault.get_entry(service, username)
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
            for i, username in enumerate(usernames, 1):
                print(f"{i}. {username}")
            
            try:
                choice = int(input("Select username number to delete: "))
                username = usernames[choice - 1]
                confirm = input(f"Are you sure you want to delete {service}/{username}? (y/N): ")
                if confirm.lower() == 'y':
                    if vault.delete_entry(service, username):
                        print("Entry deleted successfully!")
                    else:
                        print("Failed to delete entry!")
            except (ValueError, IndexError):
                print("Invalid selection!")
        
        elif choice == "6":
            try:
                length = int(input("Password length (default 16): ") or "16")
                password = vault.generate_password(length)
                print(f"Generated password: {password}")
                
                copy = input("Copy to clipboard? (y/N): ")
                if copy.lower() == 'y':
                    pyperclip.copy(password)
                    print("Password copied to clipboard!")
            except ValueError:
                print("Invalid length!")
        
        elif choice == "7":
            old_password = getpass("Enter current master password: ")
            new_password = getpass("Enter new master password: ")
            
            if len(new_password) < 8:
                print("New password must be at least 8 characters!")
                continue
                
            confirm = getpass("Confirm new master password: ")
            if new_password != confirm:
                print("New passwords do not match!")
                continue
                
            if vault.change_master_password(old_password, new_password):
                print("Master password changed successfully!")
            else:
                print("Failed to change master password!")
        
        elif choice == "8":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")
    
    vault.close()

if __name__ == "_main_":
    main()