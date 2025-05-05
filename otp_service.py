# otp_service.py
from flask_mail import Mail, Message
from app import app

mail = Mail(app)

def send_otp(email, otp):
    msg = Message('Your OTP', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'Your OTP is {otp}'
    mail.send(msg)