from getpass import getpass
from src.exceptions import ValidationError
from src.utils import validate_input
import sys

class PasswordOperations:
    def __init__(self, password_manager):
        self.pm = password_manager

    def add_new_password(self):
        """Handles new password addition"""
        site = input("Enter site name: ")
        username = input("Enter username: ")
        password = getpass("Enter password: ")
        description = input("Enter description (optional, press Enter to skip): ")
        validate_input(site, username, password, description, check_password_length=False)
        self.pm.add_password(site, username, password, description)

    def view_passwords(self):
        """Displays all stored passwords"""
        passwords = self.pm.get_passwords()
        if not passwords:
            print("No passwords found!")
        else:
            print("\nStored Passwords:")
            for site, username, password, description in passwords:
                print(f"\nSite: {site}")
                print(f"Username: {username}")
                print(f"Password: {password}")
                if description:
                    print(f"Description: {description}")

    def delete_password(self):
        """Handles password deletion"""
        site = input("Enter site to delete: ")
        username = input("Enter username to delete: ")
        self.pm.delete_password(site, username)

    def update_password(self):
        """Handles password update"""
        site = input("Enter site to update: ")
        username = input("Enter username to update: ")
        new_password = getpass("Enter new password: ")
        confirm_password = getpass("Confirm new password: ")
        
        if new_password == confirm_password:
            self.pm.update_password(site, username, new_password)
        else:
            print("Passwords don't match!")

    def view_password_history(self):
        """Displays password history for a specific account"""
        site = input("Enter site name: ")
        username = input("Enter username: ")
        
        history = self.pm.get_password_history(site, username)
        
        if not history:
            print("No password history found for this account!")
            return
            
        print(f"\nPassword history for {site} - {username}:")
        for password, date in history:
            print(f"\nChange Date: {date}")
            print(f"Old Password: {password}")

    def update_username(self):
        """Handles username update"""
        site = input("Enter site name: ")
        old_username = input("Enter current username: ")
        new_username = input("Enter new username: ")
        confirm_username = input("Confirm new username: ")
        
        if new_username == confirm_username:
            self.pm.update_username(site, old_username, new_username)
        else:
            print("Usernames don't match!")

    def update_description(self):
        """Handles description update"""
        site = input("Enter site name: ")
        username = input("Enter username: ")
        new_description = input("Enter new description (press Enter to clear): ")
        self.pm.update_description(site, username, new_description)

    def show_menu(self):
        """Displays the main menu"""
        print("\n=== Password Manager ===")
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Delete Password")
        print("4. Update Password")
        print("5. Update Username")
        print("6. Update Description")
        print("7. View Password History")
        print("8. Exit")
        return input("Choose an option (1-8): ")

    def handle_choice(self, choice):
        """Handles menu choices"""
        if choice == '1':
            self.add_new_password()
        elif choice == '2':
            self.view_passwords()
        elif choice == '3':
            self.delete_password()
        elif choice == '4':
            self.update_password()
        elif choice == '5':
            self.update_username()
        elif choice == '6':
            self.update_description()
        elif choice == '7':
            self.view_password_history()
        elif choice == '8':
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid choice!") 