from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import uuid
from datetime import datetime, timedelta
import hashlib
import os
import jwt
import logging
from dotenv import load_dotenv
from waitress import serve

load_dotenv()

app = Flask(__name__)
CORS(app)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory database (Use PostgreSQL/MongoDB in production)
users_db = {}
otp_db = {}

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")

# JWT Utility Functions
def generate_jwt(email):
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Email validation
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email) is not None

# Password strength
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password)
    )

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# OTP handling
def generate_otp(email):
    otp = "9999"  # Static for testing
    otp_db[email] = {'otp': otp, 'expiry': datetime.now() + timedelta(minutes=5)}
    return otp

def send_otp_email(email, otp):
    logger.info(f"Simulating OTP send: {otp} to {email}")
    return True

@app.route('/')
def root():
    return jsonify({'message': 'Welcome to the Flask Authentication API'}), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
    if not is_strong_password(password):
        return jsonify({'success': False, 'message': 'Weak password'}), 400
    if email in users_db:
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    users_db[email] = {
        'id': str(uuid.uuid4()),
        'full_name': full_name,
        'email': email,
        'password': hash_password(password),
        'created_at': datetime.now().isoformat()
    }

    otp = generate_otp(email)
    send_otp_email(email, otp)

    return jsonify({'success': True, 'message': 'Registered. OTP sent.', 'email': email}), 201

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json or {}
    email = data.get('email')
    entered_otp = data.get('otp')

    if not email or not entered_otp:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400
    if email not in otp_db:
        return jsonify({'success': False, 'message': 'OTP not requested'}), 404

    otp_data = otp_db[email]
    if datetime.now() > otp_data['expiry']:
        return jsonify({'success': False, 'message': 'OTP expired'}), 400
    if entered_otp != otp_data['otp']:
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 400

    del otp_db[email]
    token = generate_jwt(email)
    user = users_db[email]

    return jsonify({
        'success': True,
        'message': 'OTP verified',
        'token': token,
        'user': {
            'id': user['id'],
            'full_name': user['full_name'],
            'email': email
        }
    }), 200

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.json or {}
    email = data.get('email')

    if not email or email not in users_db:
        return jsonify({'success': False, 'message': 'Email not found'}), 404

    otp = generate_otp(email)
    send_otp_email(email, otp)

    return jsonify({'success': True, 'message': 'OTP resent'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400
    if email not in users_db or users_db[email]['password'] != hash_password(password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    otp = generate_otp(email)
    send_otp_email(email, otp)

    return jsonify({'success': True, 'message': 'OTP sent to email.', 'email': email}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    # Instruct client to delete token (token is stateless, so no server-side action)
    return jsonify({'success': True, 'message': 'Logged out successfully. Please delete token on client.'}), 200

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'success': False, 'message': 'Missing token'}), 401

    payload = decode_jwt(token)
    if not payload:
        return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401

    email = payload['email']
    user = users_db.get(email)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    return jsonify({'success': True, 'user': {
        'id': user['id'],
        'full_name': user['full_name'],
        'email': email
    }}), 200

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
