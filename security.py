from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import bleach
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv
import os
import io
import pickle
from cryptography.fernet import Fernet

# Load environment variables from .env file
load_dotenv()

SECRET_TOKEN = os.getenv("SECRET_TOKEN")
KEY = os.getenv("MODEL_KEY").encode()
fernet = Fernet(KEY)


def decrypt_model(file_path):
    # Load the encrypted model data
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the data using Fernet
    decrypted_data = fernet.decrypt(encrypted_data)

    # Return the decrypted model bytes
    return decrypted_data

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token:
            token = request.form.get('token')

        print(f'Token received: {token}')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        if token != "47fab9a45a377eb77c160e8a87be7cf8":
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)

    return decorated


def sanitize_input(input_string):
    return bleach.clean(input_string)



# Generate RSA keys (for demonstration)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

def rsa_encrypt(data):
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return encrypted_data

def rsa_decrypt(encrypted_data):
    private_key_obj = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key_obj)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


def aes_encrypt(data, key):
    key = hashlib.sha256(key.encode('utf-8')).digest()  # Ensure key length is 32 bytes
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes  # Return both IV and ciphertext

def aes_decrypt(encrypted_data, key):
    key = hashlib.sha256(key.encode('utf-8')).digest()
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted_data.decode('utf-8')
