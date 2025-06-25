import os
import base64 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass

# Constants
ITERATIONS = 100_000
KEY_LENGTH = 32  # For AES-256

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt(password: str, plaintext: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt(password: str, salt_b64: str, nonce_b64: str, ciphertext_b64: str):
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def main():
    mode = input("Encrypt or Decrypt? (e/d): ").lower()
    password = getpass("Enter password: ")

    if mode == 'e':
        plaintext = input("Enter plaintext to encrypt: ")
        encrypted = encrypt(password, plaintext)
        print("\nEncrypted Output:")
        for k, v in encrypted.items():
            print(f"{k}: {v}")
    elif mode == 'd':
        salt = input("Enter base64 salt: ")
        nonce = input("Enter base64 nonce: ")
        ciphertext = input("Enter base64 ciphertext: ")
        try:
            plaintext = decrypt(password, salt, nonce, ciphertext)
            print(f"\nDecrypted Plaintext: {plaintext}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
