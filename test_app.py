import pytest
import app
import jwt

@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    client = app.app.test_client()
    yield client

def get_jwt_for_user(email, password, otp=None, client=None):
    """Helper for email login flow."""
    # Step 1: ask for OTP
    rv = client.post('/login/email', json={"email": email, "password": password})
    assert rv.status_code == 200
    otp = app.users[email]['otp']
    # Step 2: login with OTP
    rv = client.post('/login/email', json={"email": email, "password": password, "otp": otp})
    data = rv.get_json()
    assert rv.status_code == 200
    return data['token']

def test_email_login_flow(client):
    token = get_jwt_for_user('user@example.com', 'pass123', client=client)
    rv = client.get('/protected_resource', headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 200
    assert rv.get_json()['user'] == 'user@example.com'

def test_phone_login_flow(client):
    rv = client.post('/login/phone', json={"phone": "+911234567890"})
    assert rv.status_code == 200
    otp = app.users['user@example.com']['otp']
    rv = client.post('/login/phone', json={"phone": "+911234567890", "otp": otp})
    token = rv.get_json()['token']
    rv = client.get('/protected_resource', headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 200

def test_sso_login(client):
    rv = client.post('/login/sso', json={"sso_token": "valid_sso_stub"})
    assert rv.status_code == 200
    token = rv.get_json()['token']
    rv = client.get('/protected_resource', headers={"Authorization": f"Bearer {token}"})
    assert rv.status_code == 200

def get_admin_token(client):
    return get_jwt_for_user('admin@example.com', 'admin123', client=client)

def test_invite_user_and_role_assignment(client):
    admin_token = get_admin_token(client)
    rv = client.post('/admin/invite_user', 
                     headers={"Authorization": f"Bearer {admin_token}"},
                     json={
                         "email": "viewer@test.com",
                         "password": "testviewer",
                         "phone": "+911112223345",
                         "role": "viewer"
                     })
    assert rv.status_code == 200
    assert "viewer@test.com" in app.users
    assert app.users["viewer@test.com"]["role"] == "viewer"

def test_role_change_and_rbac(client):
    admin_token = get_admin_token(client)
    # Change viewer to normal
    rv = client.post('/admin/change_role', headers={"Authorization": f"Bearer {admin_token}"},
                     json={"email": "viewer@test.com", "role": "normal"})
    assert rv.status_code == 200
    assert app.users["viewer@test.com"]["role"] == "normal"
    # Now test viewer cannot POST
    viewer_token = get_jwt_for_user("viewer@test.com", "testviewer", client=client)
    rv2 = client.post('/write_resource', headers={"Authorization": f"Bearer {viewer_token}"}, json={"content": "demo"})
    # now normal, should succeed
    assert rv2.status_code == 200

def test_viewer_has_read_only_access(client):
    # Change back to viewer
    admin_token = get_admin_token(client)
    rv = client.post('/admin/change_role', headers={"Authorization": f"Bearer {admin_token}"},
                     json={"email": "viewer@test.com", "role": "viewer"})
    assert rv.status_code == 200
    viewer_token = get_jwt_for_user("viewer@test.com", "testviewer", client=client)
    # Viewer GET should work
    rv = client.get('/protected_resource', headers={"Authorization": f"Bearer {viewer_token}"})
    assert rv.status_code == 200
    # Viewer should be forbidden on write endpoint
    rv = client.post('/write_resource', headers={"Authorization": f"Bearer {viewer_token}"}, json={"content": "fail"})
    assert rv.status_code == 403

def test_audit_log_created(client):
    admin_token = get_admin_token(client)
    rv = client.get('/admin/audit_log', headers={"Authorization": f"Bearer {admin_token}"})
    assert rv.status_code == 200
    log = rv.get_json()['log']
    assert any("invited user viewer@test.com" in line or "changed role of user viewer@test.com" in line for line in log)
