class PasswordManagerError(Exception):
    """Base exception for Password Manager"""
    pass

class ValidationError(PasswordManagerError):
    """Raised when input validation fails"""
    pass

class AuthenticationError(PasswordManagerError):
    """Raised when authentication fails"""
    pass

class DatabaseError(PasswordManagerError):
    """Raised when database operations fail"""
    pass

class FileOperationError(PasswordManagerError):
    """Raised when file operations fail"""
    pass 