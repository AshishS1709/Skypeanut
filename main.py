from flask import Flask, request, jsonify
import re
import uuid
from datetime import datetime, timedelta
import hashlib
import os

app = Flask(__name__)

# In-memory database for demonstration purposes
# In production, use a proper database like PostgreSQL, MongoDB, etc.
users_db = {}
otp_db = {}
sessions_db = {}

# Secret key for JWT
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Validate email format
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# Password strength validation
def is_strong_password(password):
    # At least 8 characters, with at least one uppercase, lowercase, and number
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate OTP (currently fixed as 9999)
def generate_otp(email):
    # Fixed OTP for now as requested
    otp = "9999"
    # Store OTP with expiration time (5 minutes)
    expiry = datetime.now() + timedelta(minutes=5)
    otp_db[email] = {
        'otp': otp,
        'expiry': expiry
    }
    return otp

# In a real system, this would send an email
def send_otp_email(email, otp):
    print(f"Sending OTP {otp} to {email}")
    # In production, integrate with an email service like SendGrid, AWS SES, etc.
    return True

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    
    # Validate inputs
    if not full_name or not email or not password:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
    
    if email in users_db:
        return jsonify({'success': False, 'message': 'Email already registered'}), 409
    
    if not is_strong_password(password):
        return jsonify({'success': False, 'message': 'Password is not strong enough'}), 400
    
    # Create user
    user_id = str(uuid.uuid4())
    users_db[email] = {
        'id': user_id,
        'full_name': full_name,
        'email': email,
        'password': hash_password(password),
        'created_at': datetime.now().isoformat()
    }
    
    # Generate and send OTP
    otp = generate_otp(email)
    send_otp_email(email, otp)
    
    return jsonify({
        'success': True,
        'message': 'Registration successful. OTP sent to email.',
        'email': email
    }), 201

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    email = data.get('email')
    entered_otp = data.get('otp')
    
    if not email or not entered_otp:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    if email not in otp_db:
        return jsonify({'success': False, 'message': 'No OTP requested for this email'}), 404
    
    stored_otp_data = otp_db[email]
    
    # Check if OTP has expired
    if datetime.now() > stored_otp_data['expiry']:
        return jsonify({'success': False, 'message': 'OTP has expired'}), 400
    
    # Verify OTP
    if entered_otp != stored_otp_data['otp']:
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 400
    
    # OTP verified, create session
    session_id = str(uuid.uuid4())
    expiry = datetime.now() + timedelta(days=30)  # 30-day session
    
    sessions_db[session_id] = {
        'user_email': email,
        'expiry': expiry
    }
    
    # Clean up the OTP
    del otp_db[email]
    
    return jsonify({
        'success': True,
        'message': 'OTP verified successfully',
        'session_id': session_id,
        'user': {
            'id': users_db[email]['id'],
            'full_name': users_db[email]['full_name'],
            'email': email
        }
    }), 200

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400
    
    if email not in users_db:
        return jsonify({'success': False, 'message': 'Email not registered'}), 404
    
    # Generate and send new OTP
    otp = generate_otp(email)
    send_otp_email(email, otp)
    
    return jsonify({
        'success': True,
        'message': 'OTP resent successfully'
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    if email not in users_db:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    if users_db[email]['password'] != hash_password(password):
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    # Generate and send OTP for two-factor authentication
    otp = generate_otp(email)
    send_otp_email(email, otp)
    
    return jsonify({
        'success': True,
        'message': 'Login successful. OTP sent to email for verification.',
        'email': email
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    session_id = data.get('session_id')
    
    if not session_id or session_id not in sessions_db:
        return jsonify({'success': False, 'message': 'Invalid session'}), 401
    
    # Remove session
    del sessions_db[session_id]
    
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200

# Helper function to check session validity
def is_valid_session(session_id):
    if session_id not in sessions_db:
        return False
    
    session_data = sessions_db[session_id]
    
    if datetime.now() > session_data['expiry']:
        del sessions_db[session_id]
        return False
    
    return True

# Example protected route
@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    session_id = request.headers.get('Authorization')
    
    if not session_id or not is_valid_session(session_id):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user_email = sessions_db[session_id]['user_email']
    user_data = users_db[user_email]
    
    return jsonify({
        'success': True,
        'user': {
            'id': user_data['id'],
            'full_name': user_data['full_name'],
            'email': user_email
        }
    }), 200

if __name__ == '__main__':
    app.run(debug=True)