PASSWORD MANAGER
===============

A secure password management application with encryption and password history tracking.

FEATURES
--------
* AES encryption for secure storage
* Master password protection
* Password history tracking
* Username and description management
* Input validation and sanitization
* Hidden file storage
* SQL injection prevention

REQUIREMENTS
-----------
* Python 3.7+
* Required packages:
  - cryptography>=41.0.7
  - cffi>=1.16.0
  - pycparser>=2.21

INSTALLATION
-----------
1. Clone the repository:
   cd password-manager

2. Install required packages:
   pip install -r requirements.txt

3. Run the application:
   python password_manager.py

USAGE
-----
Available Operations:
1. Add Password     - Store new credentials
2. View Passwords   - List all stored passwords
3. Delete Password  - Remove stored credentials
4. Update Password  - Change existing password
5. Update Username  - Modify username for existing entry
6. Update Description - Add/modify description
7. View Password History - Check password change history
8. Exit            - Safely close the application

SECURITY FEATURES
----------------
* AES encryption for password storage
* Salted password hashing for master password
* Hidden file storage for sensitive data
* Input validation and sanitization
* SQL injection prevention
* Secure password history tracking

PROJECT STRUCTURE
----------------
password_manager/
│
├── src/
│   ├── config.py        # Configuration settings
│   ├── exceptions.py    # Custom exceptions
│   ├── utils.py         # Utility functions
│   ├── encryption.py    # Encryption operations
│   └── database/        # Database operations
│
├── password_manager.py  # Main application
├── password_operations.py # User operations
├── requirements.txt     # Dependencies
└── README.txt          # Documentation

BEST PRACTICES
-------------
* Use a strong master password
* Regularly update passwords
* Keep backup of the database file
* Don't share your master password
* Ensure your system is secure

SECURITY NOTES
-------------
* All passwords are encrypted using Fernet (symmetric encryption)
* Master password is hashed with salt using PBKDF2
* Sensitive files are stored as hidden files
* Input validation prevents SQL injection
* Password history is maintained securely

LICENSE
-------
MIT License

DISCLAIMER
----------
This is a demonstration project. While it implements several security measures,
please review the security implications before using it for sensitive data. 
