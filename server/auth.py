"""
Modulo de autenticacao e seguranca da aplicacao.

Fornece funcionalidades para hash e verificacao de palavras-passe,
criacao e validacao de tokens assinados, gestao de sessoes de administrador,
tokens CSRF e sessoes de utilizadores de limpeza.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

from .config import ADMIN_SESSION_SECONDS, ADMIN_TOKEN, CSRF_TOKEN_SECONDS
from .utils import get_cookie


# ==========================================================
# Autenticacao - Palavras-passe
# ==========================================================

def hash_password(password):
    """Gera um hash seguro para uma palavra-passe usando PBKDF2-SHA256.

    Args:
        password (str): Palavra-passe em texto simples.

    Returns:
        str: String formatada com o algoritmo, salt e hash.
    """
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 210_000)
    return f"pbkdf2_sha256${salt}${password_hash.hex()}"


def verify_password(password, stored_hash):
    """Verifica se uma palavra-passe corresponde ao hash armazenado.

    Args:
        password (str): Palavra-passe em texto simples.
        stored_hash (str): Hash armazenado no formato algoritmo$salt$hash.

    Returns:
        bool: True se a palavra-passe corresponder, False caso contrario.
    """
    try:
        algorithm, salt, expected_hash = stored_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 210_000)
    return hmac.compare_digest(actual_hash.hex(), expected_hash)


# ==========================================================
# Tokens assinados
# ==========================================================

def _sign(value):
    """Gera uma assinatura HMAC-SHA256 para um valor usando o token de administrador.

    Args:
        value (str): Valor a ser assinado.

    Returns:
        str: Assinatura hexadecimal.
    """
    return hmac.new(ADMIN_TOKEN.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _b64_encode(payload):
    """Codifica um payload em base64 URL-safe sem padding.

    Args:
        payload (dict): Dicionario a codificar.

    Returns:
        str: String base64 URL-safe.
    """
    return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")


def _b64_decode(value):
    """Descodifica uma string base64 URL-safe para um dicionario.

    Args:
        value (str): String base64 URL-safe.

    Returns:
        dict: Payload descodificado.
    """
    return json.loads(base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8"))


def create_signed_token(kind, ttl_seconds):
    """Cria um token assinado com validade temporal.

    Args:
        kind (str): Tipo de token (ex: "admin-session", "csrf").
        ttl_seconds (int): Tempo de vida em segundos.

    Returns:
        str: Token no formato payload.assinatura.
    """
    payload = {"kind": kind, "nonce": secrets.token_urlsafe(24), "exp": int(time.time()) + ttl_seconds}
    encoded = _b64_encode(payload)
    return f"{encoded}.{_sign(encoded)}"


def verify_signed_token(token, kind):
    """Verifica a validade de um token assinado.

    Args:
        token (str): Token no formato payload.assinatura.
        kind (str): Tipo esperado do token.

    Returns:
        bool: True se o token for valido e do tipo correto, False caso contrario.
    """
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


# ==========================================================
# Autenticacao - Administrador
# ==========================================================

def create_admin_session_token():
    """Cria um token de sessao para administrador.

    Returns:
        str: Token de sessao assinado com validade de ADMIN_SESSION_SECONDS.
    """
    return create_signed_token("admin-session", ADMIN_SESSION_SECONDS)


def valid_admin_cookie(headers):
    """Verifica se existe um cookie de administrador valido nos cabecalhos HTTP.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.

    Returns:
        bool: True se o cookie admin_token for valido, False caso contrario.
    """
    return verify_signed_token(get_cookie(headers, "admin_token"), "admin-session")


def valid_admin_bearer(headers):
    """Verifica se o token no cabecalho Authorization corresponde ao ADMIN_TOKEN.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.

    Returns:
        bool: True se o token Bearer for valido, False caso contrario.
    """
    auth_header = headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    return bool(token and hmac.compare_digest(token, ADMIN_TOKEN))


# ==========================================================
# Protecao CSRF
# ==========================================================

def get_or_create_csrf_token(headers):
    """Obtem o token CSRF existente ou cria um novo se invalido/expirado.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.

    Returns:
        tuple: (token, was_created) onde token e o CSRF valido e was_created
               indica se foi necessario gerar um novo token.
    """
    current = get_cookie(headers, "csrf_token")
    if verify_signed_token(current, "csrf"):
        return current, False
    return create_signed_token("csrf", CSRF_TOKEN_SECONDS), True


def valid_csrf(headers, form):
    """Valida o token CSRF entre o cookie e o formulario.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.
        form (dict): Dados do formulario enviado.

    Returns:
        bool: True se o CSRF for valido, False caso contrario.
    """
    cookie_token = get_cookie(headers, "csrf_token")
    form_token = str(form.get("csrf_token", ""))
    return bool(form_token and hmac.compare_digest(cookie_token, form_token) and verify_signed_token(form_token, "csrf"))


# ==========================================================
# Sessoes de utilizadores de limpeza
# ==========================================================

def get_cleaner_session_token(headers):
    """Extrai o token de sessao do utilizador de limpeza dos cabecalhos.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.

    Returns:
        str: Token de sessao ou string vazia se nao existir.
    """
    return get_cookie(headers, "cleaner_session")
