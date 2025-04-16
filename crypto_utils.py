# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key.decode('utf-8'), private_key.decode('utf-8')

def encrypt_with_public_key(message, public_key_str):
    public_key = RSA.import_key(public_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_with_private_key(encrypted_message_b64, private_key_str):
    private_key = RSA.import_key(private_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted_message_b64.encode('utf-8'))
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode('utf-8')
