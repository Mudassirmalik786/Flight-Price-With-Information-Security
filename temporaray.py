from dotenv import load_dotenv
import os
load_dotenv()

SECRET_TOKEN = os.getenv("SECRET_TOKEN")
print("Token Loaded:", SECRET_TOKEN)