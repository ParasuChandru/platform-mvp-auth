# Platform MVP - Authentication & Roles Microservice

This repository hosts the authentication & role management service for the Platform MVP (Epic RBTES-365).

## Features
- Multi-mode authentication: Email+Password+OTP, Phone+OTP, SSO stub
- JWT-based session management
- Role storage (Admin, Normal, Viewer)
- Simulated OTP delivery
- Simple access-protected endpoint for demonstration
- Human-readable error messages

## Usage
1. `pip install flask pyjwt`
2. `python app.py`
3. Use endpoints:
    - `/login/email` (POST): {"email":..., "password":...} then {"email":..., "password":..., "otp":...}
    - `/login/phone` (POST): {"phone":...} then {"phone":..., "otp":...}
    - `/login/sso` (POST): {"sso_token": "valid_sso_stub"}
    - `/protected_resource` (GET): Header `Authorization: Bearer <token>`

## Next Steps
- Add secure password hashing (bcrypt/scrypt)
- Integrate real OTP/email/SMS service
- Add SSO integration (Google, Azure, etc.)
- Extend RBAC for resource-level permissions
- Add proper production configs and environment separation

## Epic Reference
Scoped for: RBTES-365

## License
MIT