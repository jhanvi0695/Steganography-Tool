import base64
import hashlib
from Crypto.Cipher import AES

def encrypt_message(message, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(encrypted_message, password):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        key = hashlib.sha256(password.encode()).digest()
        nonce = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()
    except:
        return "Incorrect Password or Corrupted Data"
