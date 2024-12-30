import sqlite3
from datetime import datetime
from ..exceptions import DatabaseError
from ..config import DATABASE_FILE, DB_TIMEOUT
from ..utils import sanitize_input, make_file_hidden
from ..encryption import Encryption

class DatabaseManager:
    def __init__(self, cipher_suite):
        self.db_name = DATABASE_FILE
        self.cipher_suite = cipher_suite
        self._init_database()
        self._make_db_hidden()

    def _init_database(self):
        """Initializes the database"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        
        # Main passwords table with description field
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                    (site TEXT, 
                     username TEXT, 
                     password TEXT,
                     description TEXT DEFAULT '')''')
        
        # Password history table
        c.execute('''CREATE TABLE IF NOT EXISTS password_history
                    (site TEXT, 
                     username TEXT, 
                     old_password TEXT,
                     changed_date TEXT)''')
        
        conn.commit()
        conn.close()

    def _make_db_hidden(self):
        """Makes the database file hidden"""
        make_file_hidden(self.db_name)

    def add_password(self, site, username, password, description=''):
        """Adds a new password with optional description"""
        try:
            site = sanitize_input(site)
            username = sanitize_input(username)
            description = sanitize_input(description)
            
            encrypted_password = self.cipher_suite.encrypt(password.encode())
            query = "INSERT INTO passwords VALUES (?, ?, ?, ?)"
            self._execute_query(query, (site, username, encrypted_password, description))
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to add password: {e}")

    def get_passwords(self):
        """Retrieves and decrypts all passwords"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("SELECT site, username, password, description FROM passwords")
        passwords = c.fetchall()
        conn.close()

        decrypted_passwords = []
        for site, username, encrypted_password, description in passwords:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
            decrypted_passwords.append((site, username, decrypted_password, description))
        return decrypted_passwords

    def delete_password(self, site, username):
        """Deletes a password"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("DELETE FROM passwords WHERE site=? AND username=?", 
                 (site, username))
        conn.commit()
        conn.close()
        return True

    def update_password(self, site, username, new_password):
        """Updates a password and saves the old one to history"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        
        # Get current password
        c.execute("SELECT password FROM passwords WHERE site=? AND username=?", 
                 (site, username))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return False
            
        old_password = result[0]
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save old password to history
        c.execute("""INSERT INTO password_history 
                    (site, username, old_password, changed_date) 
                    VALUES (?, ?, ?, ?)""",
                 (site, username, old_password, current_date))
        
        # Update with new password
        encrypted_password = self.cipher_suite.encrypt(new_password.encode())
        c.execute("""UPDATE passwords 
                    SET password=? 
                    WHERE site=? AND username=?""", 
                 (encrypted_password, site, username))
        
        conn.commit()
        conn.close()
        return True

    def get_password_history(self, site, username):
        """Retrieves password history for a specific account"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute("""SELECT old_password, changed_date 
                    FROM password_history 
                    WHERE site=? AND username=?
                    ORDER BY changed_date DESC""", 
                 (site, username))
        history = c.fetchall()
        conn.close()

        decrypted_history = []
        for encrypted_password, date in history:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
            decrypted_history.append((decrypted_password, date))
        return decrypted_history

    def update_username(self, site, old_username, new_username):
        """Updates username for an existing account"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        
        # Check if account exists
        c.execute("SELECT * FROM passwords WHERE site=? AND username=?", 
                 (site, old_username))
        if not c.fetchone():
            conn.close()
            return False
            
        # Update username in passwords table
        c.execute("""UPDATE passwords 
                    SET username=? 
                    WHERE site=? AND username=?""", 
                 (new_username, site, old_username))
        
        # Update username in history table
        c.execute("""UPDATE password_history 
                    SET username=? 
                    WHERE site=? AND username=?""", 
                 (new_username, site, old_username))
        
        conn.commit()
        conn.close()
        return True

    def update_description(self, site, username, new_description):
        """Updates description for an existing account"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        
        c.execute("""UPDATE passwords 
                    SET description=? 
                    WHERE site=? AND username=?""", 
                 (new_description, site, username))
        
        rows_affected = c.rowcount
        conn.commit()
        conn.close()
        return rows_affected > 0

    def _execute_query(self, query, params=None):
        """Executes a database query with error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_name, timeout=DB_TIMEOUT)
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            conn.commit()
            return cursor
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if conn:
                conn.close() 