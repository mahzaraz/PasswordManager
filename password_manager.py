from cryptography.fernet import Fernet
from getpass import getpass
import sys
import os
import platform
from src.exceptions import (
    PasswordManagerError, AuthenticationError, 
    ValidationError, FileOperationError, DatabaseError
)
from src.config import (
    MASTER_KEY_FILE, ENCRYPTION_KEY_FILE, 
    MAX_LOGIN_ATTEMPTS, HASH_ITERATIONS,
    MIN_PASSWORD_LENGTH
)
from src.utils import validate_input, make_file_hidden, get_hidden_path
from src.database.database_manager import DatabaseManager
from password_operations import PasswordOperations
from src.encryption import PasswordHasher, Encryption

class PasswordManager:
    def __init__(self):
        try:
            self._initialize_manager()
        except PasswordManagerError as e:
            print(f"Initialization failed: {e}")
            sys.exit(1)

    def _initialize_manager(self):
        """Initializes the password manager"""
        self.master_password_file = get_hidden_path(MASTER_KEY_FILE)
        self.key_file = get_hidden_path(ENCRYPTION_KEY_FILE)
        self.password_hasher = PasswordHasher()
        
        if not self._check_master_password_exists():
            self._create_master_password()
        
        if not self._verify_master_password():
            raise AuthenticationError("Authentication failed")
            
        self.key = self._load_or_generate_key()
        self.cipher_suite = Encryption.get_cipher_suite(self.key)
        self.db_manager = DatabaseManager(self.cipher_suite)

    def _check_master_password_exists(self):
        """Checks if master password file exists"""
        return os.path.exists(self.master_password_file)

    def _create_master_password(self):
        """Creates a new master password"""
        while True:
            try:
                master_pass = getpass("Create new master password: ")
                confirm_pass = getpass("Confirm master password: ")
                
                # Validate master password length
                if len(master_pass) < MIN_PASSWORD_LENGTH:
                    print(f"Master password must be at least {MIN_PASSWORD_LENGTH} characters long!")
                    continue
                
                if master_pass == confirm_pass:
                    hashed_password = self.password_hasher.hash_password(master_pass)
                    with open(self.master_password_file, 'wb') as f:
                        f.write(hashed_password)
                    make_file_hidden(self.master_password_file)
                    print("Master password created successfully!")
                    break
                else:
                    print("Passwords don't match! Try again.")
            except Exception as e:
                raise FileOperationError(f"Failed to create master password: {e}")

    def _verify_master_password(self):
        """Verifies the master password"""
        attempts = 3
        while attempts > 0:
            try:
                master_pass = getpass("Enter master password: ")
                
                with open(self.master_password_file, 'rb') as f:
                    stored_password = f.read()

                if self.password_hasher.verify_password(stored_password, master_pass):
                    return True
                
                attempts -= 1
                print(f"Wrong password! Attempts remaining: {attempts}")
            except Exception as e:
                raise FileOperationError(f"Failed to verify master password: {e}")
        
        return False

    def _load_or_generate_key(self):
        """Loads existing encryption key or generates a new one"""
        try:
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            try:
                key = Encryption.generate_key()
                with open(self.key_file, 'wb') as key_file:
                    key_file.write(key)
                make_file_hidden(self.key_file)
                return key
            except Exception as e:
                raise FileOperationError(f"Failed to generate or save encryption key: {e}")

    def add_password(self, site, username, password, description=''):
        """Adds a new password with validation"""
        try:
            validate_input(site, username, password, description)
            self.db_manager.add_password(site, username, password, description)
            print("Password added successfully!")
        except (ValidationError, DatabaseError) as e:
            print(f"Error: {e}")

    def get_passwords(self):
        """Retrieves all passwords"""
        try:
            return self.db_manager.get_passwords()
        except DatabaseError as e:
            print(f"Error retrieving passwords: {e}")
            return []

    def delete_password(self, site, username):
        """Deletes a password"""
        try:
            if self.db_manager.delete_password(site, username):
                print("Password deleted successfully!")
            else:
                print("Password not found!")
        except DatabaseError as e:
            print(f"Error deleting password: {e}")

    def update_password(self, site, username, new_password):
        """Updates an existing password"""
        try:
            validate_input(site, username, new_password)
            if self.db_manager.update_password(site, username, new_password):
                print("Password updated successfully!")
            else:
                print("Site and username not found!")
        except (ValidationError, DatabaseError) as e:
            print(f"Error updating password: {e}")

    def get_password_history(self, site, username):
        """Retrieves password history"""
        try:
            return self.db_manager.get_password_history(site, username)
        except DatabaseError as e:
            print(f"Error retrieving password history: {e}")
            return []

    def update_username(self, site, old_username, new_username):
        """Updates username for an existing account"""
        try:
            validate_input(site, old_username, new_username)
            if self.db_manager.update_username(site, old_username, new_username):
                print("Username updated successfully!")
            else:
                print("Site and username not found!")
        except (ValidationError, DatabaseError) as e:
            print(f"Error updating username: {e}")

    def update_description(self, site, username, new_description):
        """Updates description for an existing account"""
        try:
            validate_input(site, username, new_description)
            if self.db_manager.update_description(site, username, new_description):
                print("Description updated successfully!")
            else:
                print("Site and username not found!")
        except (ValidationError, DatabaseError) as e:
            print(f"Error updating description: {e}")

def main():
    try:
        pm = PasswordManager()
        operations = PasswordOperations(pm)
        
        while True:
            try:
                choice = operations.show_menu()
                operations.handle_choice(choice)
            except PasswordManagerError as e:
                print(f"Operation failed: {e}")
            except KeyboardInterrupt:
                print("\nExiting safely...")
                sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 