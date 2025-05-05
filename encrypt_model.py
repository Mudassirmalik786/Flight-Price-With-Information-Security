from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

load_dotenv()

KEY = os.getenv("MODEL_KEY").encode()
fernet = Fernet(KEY)

# Encrypt model
with open("models/c1_flight_rf.pkl", "rb") as file:
    encrypted_data = fernet.encrypt(file.read())

with open("models/c1_flight_model_encrypted.pkl", "wb") as enc_file:
    enc_file.write(encrypted_data)

print("Model encrypted successfully.")
