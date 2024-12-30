import re
import platform
from .exceptions import ValidationError
from .config import MIN_PASSWORD_LENGTH, MAX_DESCRIPTION_LENGTH

def validate_input(site, username, password, description='', check_password_length=False):
    """Validates user input for password operations"""
    if not site or not username or not password:
        raise ValidationError("Site, username and password cannot be empty")
    
    # Password length check only if check_password_length is True
    if check_password_length and len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
    
    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise ValidationError(f"Description cannot exceed {MAX_DESCRIPTION_LENGTH} characters")
    
    # Basic site name validation
    if not re.match(r'^[\w\-\.]+$', site):
        raise ValidationError("Site name contains invalid characters")
    
    # Basic username validation
    if not re.match(r'^[\w\-\.@]+$', username):
        raise ValidationError("Username contains invalid characters")

def sanitize_input(text):
    """Sanitizes user input to prevent SQL injection"""
    if not text:
        return text
    return re.sub(r'[;\'\"\\]', '', text)

def make_file_hidden(filepath):
    """Makes a file hidden in the file system"""
    if platform.system() == 'Windows':
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(filepath, 2)  # 2 = Hidden attribute

def get_hidden_path(filename):
    """Creates a hidden file path based on the operating system"""
    if platform.system() == 'Windows':
        return filename
    return filename  # For Unix-like systems, dot prefix is enough 