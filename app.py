from flask import Flask, request, jsonify
import jwt
import datetime
import random
import functools
import os

app = Flask(__name__)
SECRET_KEY = 'CHANGE_THIS_IN_PRODUCTION'

# Simulated storage
users = {
    'user@example.com': {'password': 'pass123', 'phone': '+911234567890', 'role': 'normal', 'otp': None},
    'admin@example.com': {'password': 'admin123', 'phone': '+919876543210', 'role': 'admin', 'otp': None},
}
otp_storage = {}

AUDIT_LOG_FILE = 'audit_log.txt'

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

def write_audit_log(entry):
    ts = datetime.datetime.utcnow().isoformat()
    with open(AUDIT_LOG_FILE, 'a') as f:
        f.write(f'[{ts}] {entry}\n')

# Decorator for RBAC

def require_role(*roles):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': 'Authorization required.'}), 401
            try:
                token = auth_header.split(' ')[1]
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                user_role = payload.get('role')
                email = payload.get('email')
                if user_role not in roles:
                    return jsonify({'error': f'Access denied: must be one of {roles}'}), 403
                # Attach user info to request context
                request.user_email = email
                request.user_role = user_role
            except Exception:
                return jsonify({'error': 'Invalid or expired token.'}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator

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

# ----------- Role Management Endpoints ------------

@app.route('/admin/invite_user', methods=['POST'])
@require_role('admin')
def invite_user():
    data = request.json
    new_email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
    role = data.get('role', 'viewer').lower()
    if not (new_email and password and phone and role in ['admin', 'normal', 'viewer']):
        return jsonify({'error': 'Missing or invalid parameters.'}), 400
    if new_email in users:
        return jsonify({'error': 'User with this email already exists.'}), 400
    users[new_email] = {'password': password, 'phone': phone, 'role': role, 'otp': None}
    write_audit_log(f"Admin {request.user_email} invited user {new_email} as {role}.")
    return jsonify({'msg': f'User {new_email} invited with role {role}.'})

@app.route('/admin/change_role', methods=['POST'])
@require_role('admin')
def change_role():
    data = request.json
    target_email = data.get('email')
    new_role = data.get('role', '').lower()
    if not (target_email and new_role in ['admin', 'normal', 'viewer']):
        return jsonify({'error': 'Missing or invalid parameters.'}), 400
    if target_email not in users:
        return jsonify({'error': f'User {target_email} does not exist.'}), 404
    old_role = users[target_email]['role']
    users[target_email]['role'] = new_role
    write_audit_log(f"Admin {request.user_email} changed role of user {target_email} from {old_role} to {new_role}.")
    return jsonify({'msg': f'Role for {target_email} changed from {old_role} to {new_role}.'})

# ----------- RBAC Protected Resource ------------

@app.route('/protected_resource', methods=['GET'])
@require_role('admin', 'normal', 'viewer')
def protected_resource():
    # Viewers can only GET, not write/post (all others GET allowed for demo)
    return jsonify({'msg': 'Protected data.', 'user': request.user_email, 'role': request.user_role})

@app.route('/write_resource', methods=['POST'])
@require_role('admin', 'normal')
def write_resource():
    # Only admin/normal can POST/write; viewers are denied
    payload = request.get_json()
    content = payload.get('content')
    return jsonify({'msg': f'Write successful. Data: {content}', 'user': request.user_email})

# ----------- View Audit Log ------------

@app.route('/admin/audit_log', methods=['GET'])
@require_role('admin')
def view_audit_log():
    if not os.path.exists(AUDIT_LOG_FILE):
        return jsonify({'log': []})
    with open(AUDIT_LOG_FILE, 'r') as f:
        log = f.readlines()
    return jsonify({'log': log})

# ----------- Run ------------

if __name__ == '__main__':
    app.run(debug=True)
