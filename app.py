from flask import Flask, request, jsonify
import jwt
import datetime
import random

app = Flask(__name__)
SECRET_KEY = 'CHANGE_THIS_IN_PRODUCTION'

# Simulated storage
users = {
    'user@example.com': {'password': 'pass123', 'phone': '+911234567890', 'role': 'normal', 'otp': None},
    'admin@example.com': {'password': 'admin123', 'phone': '+919876543210', 'role': 'admin', 'otp': None},
}
otp_storage = {}

# ----------- Utilities ------------

def generate_otp():
    return str(random.randint(100000, 999999))

def create_jwt(email):
    payload = {'email': email, 'role': users[email]['role'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def send_otp(phone):
    otp = generate_otp()
    otp_storage[phone] = otp
    print(f"Simulated sending OTP {otp} to {phone}")
    return otp

# ----------- Routes ------------

@app.route('/login/email', methods=['POST'])
def login_email():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    otp = data.get('otp')
    user = users.get(email)

    if not user:
        return jsonify({'error': 'Email not registered.'}), 404

    if user['password'] != password:
        return jsonify({'error': 'Incorrect password.'}), 401

    # OTP option
    if otp:
        if user['otp'] and user['otp'] == otp:
            token = create_jwt(email)
            user['otp'] = None
            return jsonify({'msg': 'Login successful (OTP verified).', 'token': token})
        else:
            return jsonify({'error': 'Invalid OTP.'}), 401
    else:
        # Generate and send OTP for extra security step
        otp = generate_otp()
        user['otp'] = otp
        print(f"Simulated sending OTP {otp} to {user['phone']}")
        return jsonify({'msg': 'OTP sent to your registered phone.'})

@app.route('/login/phone', methods=['POST'])
def login_phone():
    data = request.json
    phone = data.get('phone')
    otp = data.get('otp')
    email = None
    for user_email, info in users.items():
        if info['phone'] == phone:
            email = user_email
            break
    if not email:
        return jsonify({'error': 'Phone not registered.'}), 404

    if not otp:
        otp = send_otp(phone)
        users[email]['otp'] = otp
        return jsonify({'msg': 'OTP sent to your phone.'})
    else:
        if users[email]['otp'] == otp:
            token = create_jwt(email)
            users[email]['otp'] = None
            return jsonify({'msg': 'Login successful.', 'token': token})
        else:
            return jsonify({'error': 'Invalid OTP.'}), 401

@app.route('/login/sso', methods=['POST'])
def login_sso():
    data = request.json
    sso_token = data.get('sso_token')
    # Integrate with OAuth2 (Google, Azure, etc.) in real systems
    # Here, we simulate SSO
    if sso_token == 'valid_sso_stub':
        email = 'user@example.com'  # typically parsed from sso_token payload!
        token = create_jwt(email)
        return jsonify({'msg': 'SSO Login successful.', 'token': token})
    else:
        return jsonify({'error': 'SSO authentication failed.'}), 401

@app.route('/protected_resource', methods=['GET'])
def protected_resource():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Auth required.'}), 401
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'msg': 'Protected data.', 'user': payload['email'], 'role': payload['role']})
    except Exception:
        return jsonify({'error': 'Invalid or expired token.'}), 401

# ----------- Run ------------

if __name__ == '__main__':
    app.run(debug=True)
