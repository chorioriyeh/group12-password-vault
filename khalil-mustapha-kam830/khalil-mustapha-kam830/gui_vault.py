import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import pyperclip
from main import PasswordVault   # reuse your vault class

class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Vault")
        self.vault = PasswordVault()
        self.vault.initialize_db()
        self.show_startup()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_startup(self):
        self.clear_frame()
        tk.Label(self.root, text="Password Vault", font=("Arial", 16)).pack(pady=10)

        tk.Button(self.root, text="Create New Vault", command=self.create_vault).pack(pady=5)
        tk.Button(self.root, text="Unlock Vault", command=self.unlock_vault).pack(pady=5)

    def create_vault(self):
        pwd = simpledialog.askstring("Master Password", "Enter new master password:", show="*")
        confirm = simpledialog.askstring("Confirm Password", "Re-enter master password:", show="*")
        if not pwd or len(pwd) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return
        if pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if self.vault.setup_vault(pwd):
            messagebox.showinfo("Success", "Vault created successfully!")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Vault already exists!")

    def unlock_vault(self):
        pwd = simpledialog.askstring("Unlock Vault", "Enter master password:", show="*")
        if pwd and self.vault.unlock_vault(pwd):
            messagebox.showinfo("Success", "Vault unlocked successfully!")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Invalid master password!")

    def show_main_menu(self):
        self.clear_frame()
        tk.Label(self.root, text="Main Menu", font=("Arial", 14)).pack(pady=10)

        buttons = [
            ("Add Password", self.add_password),
            ("Retrieve Password", self.retrieve_password),
            ("List Services", self.list_services),
            ("View Entry Details", self.view_entry),
            ("Delete Entry", self.delete_entry),
            ("Generate Password", self.generate_password),
            ("Change Master Password", self.change_master),
            ("Exit", self.root.quit)
        ]
        for text, cmd in buttons:
            tk.Button(self.root, text=text, width=25, command=cmd).pack(pady=3)

    def add_password(self):
        service = simpledialog.askstring("Add", "Service:")
        username = simpledialog.askstring("Add", "Username:")
        pwd = simpledialog.askstring("Add", "Password (leave blank to auto-generate):", show="*")
        if not pwd:
            pwd = self.vault.generate_password()
            messagebox.showinfo("Generated", f"Generated password: {pwd}")
        notes = simpledialog.askstring("Add", "Notes (optional):")
        if self.vault.add_password(service, username, pwd, notes):
            messagebox.showinfo("Success", "Password saved.")
        else:
            messagebox.showerror("Error", "Failed to save password.")

    def retrieve_password(self):
        service = simpledialog.askstring("Retrieve", "Service:")
        usernames = self.vault.list_entries(service)
        if not usernames:
            messagebox.showwarning("Not Found", "No entries for this service.")
            return
        username = simpledialog.askstring("Retrieve", f"Usernames found: {', '.join(usernames)}\nEnter username:")
        if username not in usernames:
            messagebox.showerror("Error", "Invalid username.")
            return
        pwd = self.vault.get_password(service, username)
        if pwd:
            if messagebox.askyesno("Password", f"Password: {pwd}\n\nCopy to clipboard?"):
                pyperclip.copy(pwd)
        else:
            messagebox.showerror("Error", "Password not found.")

    def list_services(self):
        services = self.vault.list_services()
        if services:
            messagebox.showinfo("Services", "\n".join(services))
        else:
            messagebox.showinfo("Empty", "No services found.")

    def view_entry(self):
        service = simpledialog.askstring("View", "Service:")
        usernames = self.vault.list_entries(service)
        if not usernames:
            messagebox.showwarning("Not Found", "No entries.")
            return
        username = simpledialog.askstring("View", f"Usernames: {', '.join(usernames)}\nEnter username:")
        entry = self.vault.get_entry(service, username)
        if entry:
            details = "\n".join([f"{k}: {v}" for k, v in entry.items()])
            messagebox.showinfo("Entry", details)
        else:
            messagebox.showerror("Error", "Entry not found.")

    def delete_entry(self):
        service = simpledialog.askstring("Delete", "Service:")
        usernames = self.vault.list_entries(service)
        if not usernames:
            messagebox.showwarning("Not Found", "No entries.")
            return
        username = simpledialog.askstring("Delete", f"Usernames: {', '.join(usernames)}\nEnter username:")
        if username in usernames and messagebox.askyesno("Confirm", f"Delete {service}/{username}?"):
            if self.vault.delete_entry(service, username):
                messagebox.showinfo("Deleted", "Entry deleted.")
            else:
                messagebox.showerror("Error", "Failed to delete.")

    def generate_password(self):
        length = simpledialog.askinteger("Generate", "Password length:", initialvalue=16)
        pwd = self.vault.generate_password(length)
        if messagebox.askyesno("Password", f"Generated: {pwd}\n\nCopy to clipboard?"):
            pyperclip.copy(pwd)

    def change_master(self):
        old = simpledialog.askstring("Change Master", "Old password:", show="*")
        new = simpledialog.askstring("Change Master", "New password:", show="*")
        confirm = simpledialog.askstring("Change Master", "Confirm new password:", show="*")
        if not new or len(new) < 8:
            messagebox.showerror("Error", "New password too short.")
            return
        if new != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if self.vault.change_master_password(old, new):
            messagebox.showinfo("Success", "Master password changed.")
        else:
            messagebox.showerror("Error", "Failed to change master password.")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()
