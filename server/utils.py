"""
Modulo de utilitarios da aplicacao de gestao de limpeza WC.

Fornece constantes de rotulagem, validacoes de entrada, funcoes de formatacao
de datas e duracoes, renderizacao de templates, processamento de cookies,
limitador de taxa de submissao e calculo de periodos do dia.
"""

import html
import re
import time
from datetime import datetime
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from .config import SPAM_MAX_ATTEMPTS, SPAM_WINDOW_SECONDS, TEMPLATE_DIR

# ==========================================================
# Rotulos e opcoes da aplicacao
# ==========================================================

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
    "in_progress": "Em Resolucao",
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

# ==========================================================
# Validacoes de entrada
# ==========================================================

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,40}$")
STUDENT_NUMBER_RE = re.compile(r"^[A-Za-z0-9_.\-/ ]{1,40}$")

# ==========================================================
# Renderizacao de templates
# ==========================================================

def render_template(name, **context):
    content = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    for key, value in context.items():
        content = content.replace("{{ " + key + " }}", str(value))
        content = content.replace("{{ " + key + " | safe }}", str(value))
    return content


# ==========================================================
# Validacoes de entrada
# ==========================================================

def escape(value):
    """Escape de HTML para prevencao de injeccao XSS.

    Args:
        value: Valor a escapar.

    Returns:
        str: Valor escapado para inclusao segura em HTML.
    """
    return html.escape("" if value is None else str(value), quote=True)


def clean_text(value, max_length, multiline=False):
    """Limpa e trunca um texto de entrada.

    Remove espacos excessivos, caracteres nulos e trunca para o comprimento maximo.

    Args:
        value (str): Texto de entrada.
        max_length (int): Comprimento maximo permitido.
        multiline (bool): Se True, preserva quebras de linha.

    Returns:
        str: Texto limpo e truncado.
    """
    text = " ".join(str(value or "").split()) if not multiline else str(value or "").strip()
    text = text.replace("\x00", "")
    return text[:max_length]


def is_valid_email(value):
    """Valida um endereco de email.

    Args:
        value (str): Email a validar.

    Returns:
        bool: True se for um email valido e com tamanho adequado.
    """
    value = str(value or "").strip()
    return len(value) <= 180 and bool(EMAIL_RE.fullmatch(value))


def is_valid_username(value):
    """Valida um nome de utilizador.

    Args:
        value (str): Nome de utilizador a validar.

    Returns:
        bool: True se for valido (apenas letras minusculas, numeros, . _ -).
    """
    return bool(USERNAME_RE.fullmatch(str(value or "")))


def is_valid_password(value):
    """Valida o comprimento de uma palavra-passe.

    Args:
        value (str): Palavra-passe a validar.

    Returns:
        bool: True se tiver entre 8 e 128 caracteres.
    """
    return isinstance(value, str) and 8 <= len(value) <= 128


def is_valid_student_number(value):
    """Valida um numero de estudante.

    Args:
        value (str): Numero de estudante a validar.

    Returns:
        bool: True se for vazio ou corresponder ao padrao permitido.
    """
    return not value or bool(STUDENT_NUMBER_RE.fullmatch(value))


# ==========================================================
# Processamento de cookies
# ==========================================================

def parse_cookies(headers):
    """Extrai e parseia os cookies dos cabecalhos HTTP.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.

    Returns:
        http.cookies.SimpleCookie: Objeto com cookies extraidos.
    """
    cookie_header = headers.get("Cookie", "")
    return SimpleCookie(cookie_header)


def get_cookie(headers, name):
    """Obtem o valor de um cookie especifico dos cabecalhos.

    Args:
        headers (http.client.HTTPMessage): Cabecalhos HTTP do pedido.
        name (str): Nome do cookie.

    Returns:
        str: Valor do cookie ou string vazia se nao existir.
    """
    morsel = parse_cookies(headers).get(name)
    return morsel.value if morsel else ""


# ==========================================================
# Formatacao de datas e duracoes
# ==========================================================

def redirect_target(path, params=None):
    """Constrói uma URL com parametros de query.

    Args:
        path (str): Caminho base.
        params (dict, optional): Parametros da query string.

    Returns:
        str: URL completa com query string.
    """
    query = urlencode(params or {})
    return path + (f"?{query}" if query else "")


def format_datetime(value):
    """Formata um valor de data/hora para exibicao legivel.

    Args:
        value: Valor de data/hora em formato ISO ou datetime.

    Returns:
        str: Data formatada como "YYYY-MM-DD HH:MM" ou string vazia.
    """
    if not value:
        return ""
    return str(value).replace("T", " ")[:16]


def parse_datetime(value):
    """Converte um valor de data/hora para objeto datetime.

    Args:
        value: Valor em formato ISO, string ou datetime.

    Returns:
        datetime: Objeto datetime ou None se a conversao falhar.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def duration_seconds(start, end):
    """Calcula a duracao em segundos entre dois timestamps.

    Args:
        start: Timestamp inicial.
        end: Timestamp final.

    Returns:
        int: Duracao em segundos ou None se algum parametro for invalido.
    """
    start_dt = parse_datetime(start)
    end_dt = parse_datetime(end)
    if not start_dt or not end_dt:
        return None
    if start_dt.tzinfo is None and end_dt.tzinfo is not None:
        start_dt = start_dt.replace(tzinfo=end_dt.tzinfo)
    if end_dt.tzinfo is None and start_dt.tzinfo is not None:
        end_dt = end_dt.replace(tzinfo=start_dt.tzinfo)
    return max(0, int((end_dt - start_dt).total_seconds()))


def format_duration(seconds):
    """Formata uma duracao em segundos para exibicao legivel.

    Args:
        seconds (int): Duracao em segundos ou None.

    Returns:
        str: Duracao formatada ou "Ainda sem dados" se None.
    """
    if seconds is None:
        return "Ainda sem dados"
    minutes = int(round(seconds / 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, mins = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {mins:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def waiting_level(created_at, status):
    """Classifica o nivel de espera de um reporte.

    Args:
        created_at: Timestamp de criacao do reporte.
        status (str): Estado atual do reporte.

    Returns:
        str: Nivel de espera: "recent", "warning", "late" ou "done".
    """
    if status in {"resolved", "canceled"}:
        return "done"
    created = parse_datetime(created_at)
    if not created:
        return "recent"
    now = datetime.now(created.tzinfo) if created.tzinfo else datetime.now()
    hours = max(0, (now - created).total_seconds() / 3600)
    if hours > 72:
        return "late"
    if hours >= 24:
        return "warning"
    return "recent"


def day_key(value):
    """Extrai uma chave curta de dia a partir de um timestamp.

    Args:
        value: Valor de data/hora.

    Returns:
        str: Data no formato "DD/MM" ou string vazia.
    """
    if not value:
        return ""
    parts = str(value)[:10].split("-")
    if len(parts) == 3:
        return f"{parts[2]}/{parts[1]}"
    return str(value)[:10]


def get_period(timestamp):
    """Extrai o periodo do dia (manha, tarde, noite) a partir de um timestamp.

    Args:
        timestamp: Valor de data/hora.

    Returns:
        str: "morning", "afternoon" ou "night".
    """
    dt = parse_datetime(timestamp)
    if not dt:
        return "morning"
    hour = dt.hour
    if 6 <= hour < 12:
        return "morning"
    elif 12 <= hour < 18:
        return "afternoon"
    else:
        return "night"


# ==========================================================
# Limitador de taxa de submissao
# ==========================================================

class SubmissionRateLimiter:
    """Limitador de taxa de submissao para prevenir spam de reportes.

    Implementa uma janela deslizante por endereco IP e local.
    """

    def __init__(self, window_seconds=SPAM_WINDOW_SECONDS, max_attempts=SPAM_MAX_ATTEMPTS):
        """Inicializa o limitador com janela e limite de tentativas.

        Args:
            window_seconds (int): Duracao da janela em segundos.
            max_attempts (int): Numero maximo de submissoes permitidas na janela.
        """
        self.window_seconds = window_seconds
        self.max_attempts = max_attempts
        self._events = {}

    def allow(self, ip_address, location_id):
        """Verifica se uma submissao e permitida e regista o evento.

        Args:
            ip_address (str): Endereco IP do cliente.
            location_id (str/int): Identificador do local.

        Returns:
            bool: True se a submissao for permitida, False se exceder o limite.
        """
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
        """Remove eventos antigos fora da janela de tempo.

        Args:
            cutoff (float): Timestamp limite para considerar eventos como antigos.
        """
        for key, events in list(self._events.items()):
            fresh = [timestamp for timestamp in events if timestamp > cutoff]
            if fresh:
                self._events[key] = fresh
            else:
                self._events.pop(key, None)
