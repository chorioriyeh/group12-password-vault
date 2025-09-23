import os
import pytest
from main import PasswordVault


def setup_db(filename="test_vault.db"):
    """Helper to reset db before each test"""
    if os.path.exists(filename):
        try:
            os.remove(filename)
        except PermissionError:
            pass
    return filename


def test_vault_setup():
    """Test vault creation and setup"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        assert vault.setup_vault("test_user", "test_password") is True
        # creating with same username should fail
        assert vault.setup_vault("test_user", "test_password") is False
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


def test_vault_unlock():
    """Test unlocking the vault"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        vault.setup_vault("test_user", "test_password")

        assert vault.unlock_vault("test_user", "test_password") is True
        assert vault.unlock_vault("test_user", "wrong_password") is False
        assert vault.unlock_vault("unknown_user", "test_password") is False
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


def test_add_and_get_password():
    """Test adding and retrieving a password"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        vault.setup_vault("test_user", "test_password")
        vault.unlock_vault("test_user", "test_password")

        assert vault.add_password("gmail", "user1", "mypassword") is True
        assert vault.get_password("gmail", "user1") == "mypassword"
        assert vault.get_password("unknown_service", "user1") is None
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


def test_update_password():
    """Test updating an existing password"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        vault.setup_vault("test_user", "test_password")
        vault.unlock_vault("test_user", "test_password")

        vault.add_password("github", "coder", "oldpass")
        assert vault.get_password("github", "coder") == "oldpass"

        vault.add_password("github", "coder", "newpass")
        assert vault.get_password("github", "coder") == "newpass"
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


def test_list_services_and_entries():
    """Test listing services and entries"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        vault.setup_vault("test_user", "test_password")
        vault.unlock_vault("test_user", "test_password")

        # initially empty
        assert vault.list_services() == []

        vault.add_password("gmail", "alice", "pw1")
        vault.add_password("gmail", "bob", "pw2")
        vault.add_password("github", "alice", "pw3")

        services = vault.list_services()
        assert set(services) == {"gmail", "github"}

        gmail_users = vault.list_entries("gmail")
        assert set(gmail_users) == {"alice", "bob"}

        github_users = vault.list_entries("github")
        assert github_users == ["alice"]
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


def test_delete_entry():
    """Test deleting an entry"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        vault.setup_vault("test_user", "test_password")
        vault.unlock_vault("test_user", "test_password")

        vault.add_password("gmail", "alice", "pw1")
        assert vault.get_password("gmail", "alice") == "pw1"

        # delete entry
        assert vault.delete_entry("gmail", "alice") is True
        assert vault.get_password("gmail", "alice") is None

        # deleting again should return False
        assert vault.delete_entry("gmail", "alice") is False
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)
