import base64
import hashlib
import hmac
import json
import secrets
import time

from .config import ADMIN_SESSION_SECONDS, ADMIN_TOKEN, CSRF_TOKEN_SECONDS
from .utils import get_cookie


def hash_password(password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 210_000)
    return f"pbkdf2_sha256${salt}${password_hash.hex()}"


def verify_password(password, stored_hash):
    try:
        algorithm, salt, expected_hash = stored_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 210_000)
    return hmac.compare_digest(actual_hash.hex(), expected_hash)


def _sign(value):
    return hmac.new(ADMIN_TOKEN.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _b64_encode(payload):
    return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")


def _b64_decode(value):
    return json.loads(base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8"))


def create_signed_token(kind, ttl_seconds):
    payload = {"kind": kind, "nonce": secrets.token_urlsafe(24), "exp": int(time.time()) + ttl_seconds}
    encoded = _b64_encode(payload)
    return f"{encoded}.{_sign(encoded)}"


def verify_signed_token(token, kind):
    if not token or "." not in token:
        return False
    encoded, signature = token.rsplit(".", 1)
    if not hmac.compare_digest(_sign(encoded), signature):
        return False
    try:
        payload = _b64_decode(encoded)
    except (ValueError, json.JSONDecodeError):
        return False
    return payload.get("kind") == kind and int(payload.get("exp", 0)) >= int(time.time())


def create_admin_session_token():
    return create_signed_token("admin-session", ADMIN_SESSION_SECONDS)


def valid_admin_cookie(headers):
    return verify_signed_token(get_cookie(headers, "admin_token"), "admin-session")


def valid_admin_bearer(headers):
    auth_header = headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    return bool(token and hmac.compare_digest(token, ADMIN_TOKEN))


def get_or_create_csrf_token(headers):
    current = get_cookie(headers, "csrf_token")
    if verify_signed_token(current, "csrf"):
        return current, False
    return create_signed_token("csrf", CSRF_TOKEN_SECONDS), True


def valid_csrf(headers, form):
    cookie_token = get_cookie(headers, "csrf_token")
    form_token = str(form.get("csrf_token", ""))
    return bool(form_token and hmac.compare_digest(cookie_token, form_token) and verify_signed_token(form_token, "csrf"))


def get_cleaner_session_token(headers):
    return get_cookie(headers, "cleaner_session")

