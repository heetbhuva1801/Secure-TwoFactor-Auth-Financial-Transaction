import pyotp
import getpass  # To securely input password
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import qrcode
import os

# AES Encryption and Decryption Functions
def generate_key(key_size=256):
    """Generates a random AES key."""
    return os.urandom(key_size // 8)  # Generate key with specified bit size

def aes_encrypt(data, key):
    """Encrypts the given data using AES (GCM mode)."""
    cipher = AES.new(key, AES.MODE_GCM)  # AES in GCM mode
    ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt and generate tag for integrity
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    """Decrypts the encrypted data using AES (GCM mode)."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Initialize cipher with nonce
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify data integrity

def generate_hmac(key, message):
    """Generates HMAC for a given message using the provided key."""
    hmac = HMAC.new(key, message, SHA256)
    return hmac.digest()

def verify_hmac(key, message, hmac_value):
    """Verifies that the provided HMAC matches the generated HMAC for the message."""
    hmac = HMAC.new(key, message, SHA256)
    try:
        hmac.hexverify(hmac_value.hex())  # Verify the provided HMAC
        return True
    except ValueError:
        return False

def generate_totp_secret(username):
    """Generates a secret key for TOTP and displays a QR code for Google Authenticator."""
    secret = pyotp.random_base32()  # Generate a random base32 secret key
    print("Your TOTP Secret Key (keep it safe):", secret)  # Optional: Print the secret for debugging
    
    # Generate a URL for Google Authenticator
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="YourAppName")
    
    # Generate the QR code
    qr = qrcode.make(totp_uri)
    qr_file_name = f"{username}_totp_qr.png"
    qr.save(qr_file_name)  # Save the QR code as a PNG file
    print(f"QR code saved as {qr_file_name}. Scan this with Google Authenticator.")
    
    return secret

# User class to encapsulate user data and functionality
class User:
    def __init__(self, username):
        self.username = username
        self.password = None
        self.totp_secret = None

    def register(self):
        """Registers the user with a password and generates a TOTP secret."""
        self.password = getpass.getpass(f"Set a password for {self.username}: ")
        self.totp_secret = generate_totp_secret(self.username)  # Generate TOTP secret key

    def authenticate(self):
        """Authenticates the user with password and TOTP."""
        password = getpass.getpass("Enter your password: ")
        if password != self.password:
            print("Invalid password!")
            return False

        totp = pyotp.TOTP(self.totp_secret)
        otp = input("Enter the TOTP code from your Google Authenticator app: ")

        # Verify the entered TOTP code
        if totp.verify(otp):
            print("Authentication successful!")
            return True
        else:
            print("Invalid TOTP code!")
            return False

# Simulation of the financial transaction process
def financial_transaction(sender, receiver, amount):
    """Simulates a financial transaction from sender to receiver."""
    data = f"Transfer {amount} from {sender.username} to {receiver.username}".encode()
    aes_key = generate_key(256)  # Generate a secure AES key

    # Generate HMAC for the original data
    hmac_value = generate_hmac(aes_key, data)

    # Encrypt the data
    nonce, ciphertext, tag = aes_encrypt(data, aes_key)
    print(f"\nEncrypted Data: {ciphertext}")

    # Simulate sending the transaction to the receiver
    print(f"\n{sender.username} is sending {amount} to {receiver.username}...")

    # Receiver process
    print(f"\n{receiver.username} is receiving the transaction...")
    
    # Receiver decrypts the data
    try:
        decrypted_data = aes_decrypt(nonce, ciphertext, tag, aes_key)
        print("Decrypted Data:", decrypted_data.decode())

        # Verify the HMAC after decryption to ensure data integrity
        if verify_hmac(aes_key, decrypted_data, hmac_value):
            print("Data integrity verified: The data has not been tampered with.")
            print(f"Transaction of {amount} from {sender.username} to {receiver.username} completed successfully.")
        else:
            print("Data integrity check failed: The data may have been tampered with.")
    except ValueError:
        print("Decryption failed: The data may have been tampered with.")

# Example usage
if __name__ == "__main__":
    # Create sender and receiver users
    sender = User("Sender")
    receiver = User("Receiver")

    # Register users
    print("Registering Sender:")
    sender.register()
    print("\nRegistering Receiver:")
    receiver.register()

    # Authenticate users
    if sender.authenticate() and receiver.authenticate():
        # Simulate a financial transaction
        amount = input("Enter the amount to transfer: ")
        financial_transaction(sender, receiver, amount)
