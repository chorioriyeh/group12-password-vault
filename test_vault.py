import os
import pytest
from main import PasswordVault

def test_vault_creation():
    """Test vault creation and basic operations"""
    # Clean up any existing test file
    test_db = "test_vault.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    vault = PasswordVault(test_db)
    vault.initialize_db()
    
    # Test vault setup
    assert vault.setup_vault("test_password") == True
    
    # Test vault unlock
    assert vault.unlock_vault("test_password") == True
    assert vault.unlock_vault("wrong_password") == False
    
    # Test password operations
    assert vault.add_password("test_service", "test_user", "test_password") == True
    assert vault.get_password("test_service", "test_user") == "test_password"
    assert vault.get_password("wrong_service", "test_user") == None
    
    # Test updating existing entry
    assert vault.add_password("test_service", "test_user", "new_password") == True
    assert vault.get_password("test_service", "test_user") == "new_password"
    
    # Test service listing
    assert "test_service" in vault.list_services()
    
    # Test entry listing
    assert "test_user" in vault.list_entries("test_service")
    
    # Test password generation
    password = vault.generate_password()
    assert len(password) == 16
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    
    # Test entry details
    entry = vault.get_entry("test_service", "test_user")
    assert entry is not None
    assert entry['service'] == "test_service"
    assert entry['username'] == "test_user"
    assert entry['password'] == "new_password"
    
    # Test master password change
    assert vault.change_master_password("test_password", "new_test_password") == True
    assert vault.unlock_vault("new_test_password") == True
    assert vault.get_password("test_service", "test_user") == "new_password"
    
    # Test entry deletion
    assert vault.delete_entry("test_service", "test_user") == True
    assert vault.get_password("test_service", "test_user") == None
    
    vault.close()
    
    # Clean up
    if os.path.exists(test_db):
        os.remove(test_db)
    
    print("All tests passed!")

if __name__ == "_main_":
    test_vault_creation()