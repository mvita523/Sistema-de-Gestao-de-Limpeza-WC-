import html
import re
import time
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from .config import SPAM_MAX_ATTEMPTS, SPAM_WINDOW_SECONDS, TEMPLATE_DIR

ISSUE_LABELS = {
    "paper": "Sem papel higienico",
    "soap": "Sem sabonete",
    "dirty": "WC sujo",
    "smell": "Mau cheiro",
    "water": "Falta de Agua",
    "other": "Outro",
}

STATUS_LABELS = {
    "pending": "Pendente",
    "resolved": "Resolvido",
    "canceled": "Cancelado",
}

USER_CATEGORY_LABELS = {
    "student": "Estudante",
    "employee": "Funcionario",
    "visitor": "Visitante",
}

LOCAL_CATEGORY_LABELS = {
    "classroom": "Sala de Aula",
    "wc": "WC",
    "office": "Gabinete",
}

LOCAL_SUBCATEGORY_OPTIONS = {
    "wc": [
        "WC do pavilhao Feminino - IP",
        "WC do pavilhao Masculino - IP",
        "WC do res-do-chao Feminino - IP",
        "WC do res-do-chao Masculino - IP",
        "WC do 1o Andar Feminino - IP",
        "WC do 1o Andar Masculino - IP",
        "WC do res-do-chao Funcionario Feminino - IP",
        "WC do res-do-chao Funcionario Masculino - IP",
        "WC do 1o Andar Funcionario Feminino - IP",
        "WC do 1o Andar Funcionario Masculino - IP",
        "WC Feminino - FD",
        "WC Masculino - FD",
        "WC Feminino - FE",
        "WC Masculino - FE",
    ],
    "classroom": [f"Sala {number}" for number in range(1, 21)],
    "office": ["IP", "FE", "FD", "Reitoria"],
}

COURSE_OPTIONS = [
    "Engenharia Informatica",
    "Contabilidade e Gestao",
    "Agronomia",
    "Enfermagem",
    "Direito",
    "Economia",
    "Medicina",
    "Funcionario",
    "Visitante",
]

PERIOD_LABELS = {
    "morning": "Manha",
    "afternoon": "Tarde",
    "night": "Noite",
}

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,40}$")
STUDENT_NUMBER_RE = re.compile(r"^[A-Za-z0-9_.\-/ ]{1,40}$")


def render_template(name, **context):
    content = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    for key, value in context.items():
        content = content.replace("{{ " + key + " }}", str(value))
    return content


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def clean_text(value, max_length, multiline=False):
    text = " ".join(str(value or "").split()) if not multiline else str(value or "").strip()
    text = text.replace("\x00", "")
    return text[:max_length]


def is_valid_email(value):
    value = str(value or "").strip()
    return len(value) <= 180 and bool(EMAIL_RE.fullmatch(value))


def is_valid_username(value):
    return bool(USERNAME_RE.fullmatch(str(value or "")))


def is_valid_password(value):
    return isinstance(value, str) and 8 <= len(value) <= 128


def is_valid_student_number(value):
    return not value or bool(STUDENT_NUMBER_RE.fullmatch(value))


def parse_cookies(headers):
    cookie_header = headers.get("Cookie", "")
    return SimpleCookie(cookie_header)


def get_cookie(headers, name):
    morsel = parse_cookies(headers).get(name)
    return morsel.value if morsel else ""


def redirect_target(path, params=None):
    query = urlencode(params or {})
    return path + (f"?{query}" if query else "")


def format_datetime(value):
    if not value:
        return ""
    return str(value).replace("T", " ")[:16]


def day_key(value):
    if not value:
        return ""
    parts = str(value)[:10].split("-")
    if len(parts) == 3:
        return f"{parts[2]}/{parts[1]}"
    return str(value)[:10]


class SubmissionRateLimiter:
    def __init__(self, window_seconds=SPAM_WINDOW_SECONDS, max_attempts=SPAM_MAX_ATTEMPTS):
        self.window_seconds = window_seconds
        self.max_attempts = max_attempts
        self._events = {}

    def allow(self, ip_address, location_id):
        now = time.monotonic()
        cutoff = now - self.window_seconds
        key = (ip_address, str(location_id))
        events = [timestamp for timestamp in self._events.get(key, []) if timestamp > cutoff]
        allowed = len(events) < self.max_attempts
        if allowed:
            events.append(now)
        self._events[key] = events
        self._cleanup(cutoff)
        return allowed

    def _cleanup(self, cutoff):
        for key, events in list(self._events.items()):
            fresh = [timestamp for timestamp in events if timestamp > cutoff]
            if fresh:
                self._events[key] = fresh
            else:
                self._events.pop(key, None)

