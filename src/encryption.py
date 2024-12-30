from cryptography.fernet import Fernet
import hashlib
import os

class PasswordHasher:
    def __init__(self):
        self.salt_length = 16
        
    def hash_password(self, password):
        """Creates a salted hash of the password"""
        salt = os.urandom(self.salt_length)
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        return salt + hashed
        
    def verify_password(self, stored_password, provided_password):
        """Verifies if the provided password matches the stored hash"""
        salt = stored_password[:self.salt_length]
        stored_hash = stored_password[self.salt_length:]
        hash_to_check = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode(),
            salt,
            100000
        )
        return hash_to_check == stored_hash

class Encryption:
    @staticmethod
    def generate_key():
        """Generates a new encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def get_cipher_suite(key):
        """Creates a cipher suite from the given key"""
        return Fernet(key) 