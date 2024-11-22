import os
import base64
from password_strength import PasswordStats
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Validate the password for sign up for master password
def check_password_strength(password):
    stats = PasswordStats(password)

    strength_score = stats.strength()
    feedback = []

    if len(password) < 8:
        feedback.append("Password should be at least 8 characters")
    if not any(char.isdigit() for char in password):
        feedback.append("Password should contain at least 1 digit.")
    if not any(char.isupper() for char in password):
        feedback.append("Password should contain at least 1 upper cased character.")
    if not any(char.islower() for char in password):
        feedback.append("Password should contain at least 1 lower cased character.")
    if not any(char in "!@#$%^&*(){}[]|\/.;''?+=-`,><:" for char in password):
        feedback.append("Password should contain at least one special character.")

    if feedback:
        return {"strength_score": strength_score, "feedback": feedback}
    else:
        return {"strength_score": strength_score, "feedback": ["Password is strong!"]} 
    
# Key Derivation Function
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm = SHA256(),
        length = 32, #AES-256 requires 32 byte key
        salt = salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# Function to encrypt password
def encrypt_password(master_password, salt, account_password):
    key = derive_key(master_password, salt)

    # Generate a random IV
    iv = os.urandom(16)

    # Encrypt the password
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the password to match AES block size
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(account_password.encode()) + padder.finalize()

    # Encrypt and encode to text for storage
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return (
        base64.b64encode(encrypted_password).decode(),
        base64.b64encode(iv).decode()
    )

# Function to decrypt password
def decrypt_password(master_password, encrypted_password, iv, salt):

    # Derive the key
    key = derive_key(master_password, salt)

    # Decrypt the password
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Remove padding
    padded_data = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    password = unpadder.update(padded_data) + unpadder.finalize()

    return password.decode()

