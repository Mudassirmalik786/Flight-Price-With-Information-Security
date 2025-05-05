from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from dotenv import load_dotenv
import bcrypt
import os
import random
import string
import bleach
import io
import pickle
import pandas as pd

# Security imports (RSA, AES, token-based)
from security import token_required, decrypt_model, rsa_encrypt, rsa_decrypt, aes_encrypt, aes_decrypt

# Chat API (GROQ/Llama simulated)
from chat_api import chat_with_model

# Mediapipe integration
from mediapipe_detect import detect_hand_gesture

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "mysecretkey")

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)

# CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": allowed_origins}})

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)

otp_store = {}

# Load and decrypt ML model
model_bytes = decrypt_model("models/c1_flight_model_encrypted.pkl")
model = pickle.load(io.BytesIO(model_bytes))


@app.route("/")
@cross_origin()
def landing():
    return render_template('landing.html')



@app.route("/home")
def home():
    if 'email' not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for('landing'))
    return render_template('home.html', email=session['email'], token="47fab9a45a377eb77c160e8a87be7cf8")


@app.route("/register", methods=["GET", "POST"])
@cross_origin()
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = bleach.clean(request.form.get("email"))
    password = bleach.clean(request.form.get("password"))

    if not email or not password:
        flash("Email and password required.", "danger")
        return redirect(url_for("register"))

    if User.query.filter_by(email=email).first():
        flash("Email already registered.", "danger")
        return redirect(url_for("register"))

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(email=email, password=hashed_pw.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()

    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = otp

    msg = Message("Your OTP", sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

    session['pending_verification_email'] = email
    flash("Check your email for the OTP.", "success")
    return redirect(url_for("verify_otp"))


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "GET":
        return render_template("verify_otp.html")

    email = session.get('pending_verification_email')
    input_otp = request.form.get("otp")
    actual_otp = otp_store.get(email)

    if input_otp == actual_otp:
        user = User.query.filter_by(email=email).first()
        user.verified = True
        db.session.commit()
        otp_store.pop(email)
        session.pop('pending_verification_email')
        flash("Email verified!", "success")
        return redirect(url_for("login"))

    flash("Invalid OTP.", "danger")
    return redirect(url_for("verify_otp"))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    # Clean input values
    email = bleach.clean(request.form.get("email"))
    password = request.form.get("password")

    # Check if user exists
    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    if not user.verified:
        flash("Verify your email first.", "warning")
        return redirect(url_for("login"))

    # Set email in session
    session['email'] = email

    # Redirect to home on successful login
    return redirect(url_for("home"))

@app.route("/predict", methods=["POST"])
@cross_origin()
@token_required
def predict():
    try:
        data = request.form
        date_dep = pd.to_datetime(data["Dep_Time"], format="%Y-%m-%dT%H:%M", errors="coerce")
        date_arr = pd.to_datetime(data["Arrival_Time"], format="%Y-%m-%dT%H:%M", errors="coerce")

        total_stops = int(data["stops"])
        duration_minutes = int(abs((date_arr - date_dep).total_seconds() / 60))

        airlines = ['Air India', 'GoAir', 'IndiGo', 'Jet Airways', 'Multiple carriers', 'Other', 'SpiceJet', 'Vistara']
        airline_ohe = [1 if data['airline'] == a else 0 for a in airlines]

        sources = ['Chennai', 'Delhi', 'Kolkata', 'Mumbai']
        source_ohe = [1 if data['Source'] == s else 0 for s in sources]

        destinations = ['Cochin', 'Delhi', 'Hyderabad', 'Kolkata']
        destination_ohe = [1 if data['Destination'] == d else 0 for d in destinations]

        features = [
            total_stops, date_dep.day, date_dep.month,
            date_dep.hour, date_dep.minute, date_arr.hour, date_arr.minute,
            duration_minutes, *airline_ohe, *source_ohe, *destination_ohe
        ]

        prediction = model.predict([features])
        output = round(prediction[0], 2)

        return render_template('home.html',prediction_text="Your Flight price is Rs. {}".format(output))
        
    except Exception as e:
        return render_template('unauthorized.html', prediction_text="Error: {}".format(str(e)))

@app.context_processor
def inject_user():
    return dict(email=session.get('email'))


@app.route("/chat", methods=["POST"])
def chat():
    prompt = bleach.clean(request.json.get("prompt"))
    if not prompt:
        return jsonify({'error': 'Prompt is required.'}), 400

    response = chat_with_model(prompt)
    return jsonify({'response': response})


@app.route("/hand-gesture", methods=["POST"])
def hand_gesture():
    image_file = request.files.get("image")
    if not image_file:
        return jsonify({'error': 'Image is required.'}), 400

    result = detect_hand_gesture(image_file)
    return jsonify({'gesture_detected': result})


@app.route("/encrypt-decrypt-test")
def encrypt_decrypt_test():
    message = "Hello Secure World"
    rsa_encrypted = rsa_encrypt(message)
    rsa_decrypted = rsa_decrypt(rsa_encrypted)

    aes_encrypted = aes_encrypt(message)
    aes_decrypted = aes_decrypt(aes_encrypted)

    return jsonify({
        'original': message,
        'rsa_encrypted': rsa_encrypted,
        'rsa_decrypted': rsa_decrypted,
        'aes_encrypted': aes_encrypted,
        'aes_decrypted': aes_decrypted
    })


@app.route('/logout')
def logout():
    # Remove the email from session
    session.pop('email', None)
    
    # Redirect to landing page
    return redirect(url_for('landing'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
