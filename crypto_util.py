from cryptography.fernet import Fernet
import hashlib

#  Generate a new encryption key
def generate_key():
    return Fernet.generate_key()

#  Encrypt message using key
def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()

#  Decrypt encrypted message using key
def decrypt_message(token, key):
    return Fernet(key).decrypt(token.encode()).decode()

#  Create a hashed password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#  Compare input password with hashed password
def check_password(input_password, stored_hash):
    return hash_password(input_password) == stored_hash