import os
import pytest
from main import PasswordVault


def setup_db(filename="test_vault.db"):
    """Helper to reset db before each test"""
    if os.path.exists(filename):
        try:
            os.remove(filename)
        except PermissionError:
            # In case previous process didn't release, retry after close
            pass
    return filename


def test_vault_setup():
    """Test vault creation and setup"""
    test_db = setup_db()
    vault = PasswordVault(test_db)
    try:
        vault.initialize_db()
        assert vault.setup_vault("test_password") is True
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
        vault.setup_vault("test_password")

        assert vault.unlock_vault("test_password") is True
        assert vault.unlock_vault("wrong_password") is False
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
        vault.setup_vault("test_password")
        vault.unlock_vault("test_password")

        assert vault.add_password("test_service", "test_user", "test_password") is True
        assert vault.get_password("test_service", "test_user") == "test_password"
        assert vault.get_password("wrong_service", "test_user") is None
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
        vault.setup_vault("test_password")
        vault.unlock_vault("test_password")

        vault.add_password("test_service", "test_user", "old_password")
        assert vault.get_password("test_service", "test_user") == "old_password"

        # Update
        assert vault.add_password("test_service", "test_user", "new_password") is True
        assert vault.get_password("test_service", "test_user") == "new_password"
    finally:
        vault.close()
        if os.path.exists(test_db):
            os.remove(test_db)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
