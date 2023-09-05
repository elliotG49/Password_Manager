
import bcrypt
import sqlite3
import re
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import base64
import time
import threading

print()
print()
print()
print("-----------------------------------------------------------------------------------------------------------")
print("Welcome to your local secure password manager")
print("-----------------------------------------------------------------------------------------------------------")
print()
print()
print()

encryption_key = None

def database_users_setup():
    connect = sqlite3.connect('password_manager.db')
    cursor = connect.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        hashed_password TEXT NOT NULL,
        salt BLOB NOT NULL,
        salt_kdf BLOB NOT NULL
    );
    ''')
    connect.commit()
    return connect, cursor

def database_entries_setup(connect, cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS site_credentials (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        site_name TEXT NOT NULL,
        username TEXT NOT NULL,
        email TEXT NOT NULL, 
        password TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    connect.commit()

def set_master_password(connect, cursor):
    print("The Requirements are as followed:")
    print("10 Characters or more")
    print("Must include lowercase letters")
    print("Must include capitals")
    print("Must include a number")
    print("Must Include a '!@#%?/*'")

    while True:
        user_input = input("Please set your master password: ")

        if len(user_input) < 10:
            print("Password should be 10 characters or more.")
        elif not re.search("[a-z]", user_input):
            print("Password should include lowercase letters.")
        elif not re.search("[A-Z]", user_input):
            print("Password should include capital letters.")
        elif not re.search("[0-9]", user_input):
            print("Password should include a number.")
        elif not re.search("[!@#%?/*]", user_input):
            print("Password should include one of '!@#%?/*'.")
        elif re.search("\s", user_input):
            print("Password should not have spaces.")
        else:
            encoded_user_input = user_input.encode()
            salt_hashing = bcrypt.gensalt()
            salt_kdf = os.urandom(16)
            hashed_user_input = bcrypt.hashpw(encoded_user_input, salt_hashing)
            cursor.execute("INSERT INTO users (hashed_password, salt , salt_kdf) VALUES (?, ?, ?)", (hashed_user_input, salt_hashing, salt_kdf))
            connect.commit()
            print("Password set successfully!")
            break

def set_encryption_key(password, salt_kdf):
    global encryption_key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_kdf,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    encryption_key = Fernet(key)

def reset_encryption_key():
    global encryption_key
    encryption_key = None
    print()
    print("Session expired! Please re-authenticate.")
    print()

def authentication(connect, cursor):
    global encryption_key
    user_input = input("Please enter your master password: ")
    encoded_user_input = user_input.encode()
    cursor.execute("SELECT hashed_password, salt, salt_kdf FROM users LIMIT 1")
    stored_hash_password, stored_salt, stored_salt_kdf = cursor.fetchone()
    hashed_input = bcrypt.hashpw(encoded_user_input, stored_salt)

    if hashed_input == stored_hash_password:
        print()
        print("Authentication Successful")
        set_encryption_key(encoded_user_input, stored_salt_kdf)
        session_timeout = threading.Timer(300, reset_encryption_key)
        session_timeout.start()
        return True
    else:
        print("Authenticaion Failed")
        return False

def create_entry(connect, cursor, encryption_key):
    site_name = input("Please enter the site name: (eg. Twitter, Facebook): ")
    username = input("Please enter the username for the site, if none, just press enter: ")
    email = input("Please enter the email used, if none, just press enter:")
    password = input("Please enter your password: ")
    password_hash = hashlib.sha512(password.encode()).hexdigest()
    print()
    user_input = input("Would you like us to check your password against our database to check how secure it is, and if its known?: (y), (n)")
    print()
    if user_input == "y":
        if password_in_file(password_hash):
            print("WARNING: This password is known and may not be secure!")
            print()
            print("Please change that password for that site immediatley!")
            print()
        else:
            print("Your password was not found in our dataset and is likely secure.")
            encrypted_site_name = encryption_key.encrypt(site_name.encode()).decode()
            encrypted_username = encryption_key.encrypt(username.encode()).decode()
            encrypted_email = encryption_key.encrypt(email.encode()).decode()
            encrypted_password = encryption_key.encrypt(password.encode()).decode()

            cursor.execute("INSERT INTO site_credentials (site_name, username, email, password) VALUES (?, ?, ?, ?)", 
                    (encrypted_site_name, encrypted_username, encrypted_email, encrypted_password))
            connect.commit()

            print("Entry added successfully!")


    elif user_input == "n":
        encrypted_site_name = encryption_key.encrypt(site_name.encode()).decode()
        encrypted_username = encryption_key.encrypt(username.encode()).decode()
        encrypted_email = encryption_key.encrypt(email.encode()).decode()
        encrypted_password = encryption_key.encrypt(password.encode()).decode()

        cursor.execute("INSERT INTO site_credentials (site_name, username, email, password) VALUES (?, ?, ?, ?)", 
                (encrypted_site_name, encrypted_username, encrypted_email, encrypted_password))
        connect.commit()

        print("Entry added successfully!")

    else:
        print("invalid input, please enter again")
        return

def password_in_file(password_hash):
    print("this may take some time, please be patient")
    print()
    time.sleep(3)
    with open('rockyou_hashed.txt', 'r', encoding='latin-1') as file:
        for line in file:
            if password_hash == line.strip():
                return True
            
        return False

def display_entries(connect, cursor, encryption_key):
    cursor.execute("SELECT site_name, username, email, password FROM site_credentials")
    credentials = cursor.fetchall()
    
    if not credentials:
        print("No credentials saved yet!")
        return
    
    print("\nYour saved credentials:")
    for idx, (encrypted_site, encrypted_username, encrypted_email, encrypted_password) in enumerate(credentials, 1):
        decrypted_site = encryption_key.decrypt(encrypted_site.encode()).decode()
        decrypted_username = encryption_key.decrypt(encrypted_username.encode()).decode()
        decrypted_email = encryption_key.decrypt(encrypted_email.encode()).decode()
        decrypted_password = encryption_key.decrypt(encrypted_password.encode()).decode()

        print(f"{idx}. Site: {decrypted_site}, Username: {decrypted_username}, Email: {decrypted_email}, Password: {decrypted_password}")

def is_master_password_set(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    return count > 0

def close_database(connect):
    connect.close()

def main():
    connect, cursor = database_users_setup()
    database_entries_setup(connect, cursor)

    if not is_master_password_set(cursor):
        set_master_password(connect, cursor)
        authenticated = False
        while not authenticated:
            authenticated = authentication(connect, cursor)
            if not authenticated:
                print("Please try again or press Ctrl+C to exit.")
    else:
        if not authentication(connect, cursor):
            print("Exiting due to failed authentication.")
            close_database(connect)
            return

    while True:
        if encryption_key is None:
            if not authentication(connect, cursor):
                print("Exiting due to failed authentication.")
                close_database(connect)
                return

        print("\nDo you want to create a new entry(1), view your passwords(2), or exit(3)?")
        user_input = input(": ")
        print()

        if user_input == "1":
            create_entry(connect, cursor, encryption_key)
        elif user_input == "2":
            display_entries(connect, cursor, encryption_key)
        elif user_input == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid input, please try again.")
    close_database(connect)

if __name__ == "__main__":
    main()