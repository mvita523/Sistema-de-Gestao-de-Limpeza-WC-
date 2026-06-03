"""
Servico de envio de notificacoes por email.

Responsavel por enviar alertas via API Brevo quando sao criados novos reportes
de ocorrencia de limpeza, notificando os destinatarios configurados.
"""

import os
import requests

from .config import DEFAULT_ADMIN_EMAIL, logger
from .database import get_cleaner_notification_emails, get_setting
from .utils import ISSUE_LABELS

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


# ==========================================================
# Envio de emails
# ==========================================================

def get_notification_email():
    """Obtem o email de notificacao configurado ou o valor por defeito.

    Returns:
        str: Endereco de email para notificacoes administrativas.
    """
    return get_setting("notification_email", DEFAULT_ADMIN_EMAIL).strip()


def get_notification_recipients():
    """Obtem a lista de destinatarios para notificacoes de novos reportes.

    Prioriza os emails dos utilizadores de limpeza com notificacoes ativadas.
    Se nao existirem, utiliza o email de notificacao configurado.

    Returns:
        list: Lista de enderecos de email dos destinatarios.
    """
    recipients = get_cleaner_notification_emails()
    fallback_email = get_notification_email()

    if not recipients and fallback_email:
        recipients.append(fallback_email)

    return recipients


def email_enabled():
    """Verifica se o envio de emails esta configurado e disponivel.

    Returns:
        bool: True se a API Brevo esta configurada e existem destinatarios, False caso contrario.
    """
    return bool(os.environ.get("BREVO_API_KEY") and get_notification_recipients())


def notify_admin_by_email(report_id, issue_type, location, description):
    """Envia uma notificacao por email para um novo reporte de ocorrencia.

    Args:
        report_id (int): Identificador do reporte criado.
        issue_type (str): Tipo de problema reportado.
        location (dict): Dados do local (name, building, floor, id).
        description (str): Descricao detalhada do problema.

    Returns:
        tuple: (sucesso, mensagem) onde sucesso e bool e mensagem e string com
               detalhe do resultado ou erro.
    """
    recipients = get_notification_recipients()

    if not email_enabled():
        logger.info("email_disabled report_id=%s", report_id)
        return False, "Email nao configurado."

    # ==========================================================
    # Construcao do corpo do email
    # ==========================================================
    body_parts = [
        f"Novo reporte WC #{report_id}",
        f"Problema: {ISSUE_LABELS[issue_type]}",
        f"Sala/WC: {location['id']}",
        f"Local: {location['name']} ({location['building']}, piso {location['floor']})",
    ]

    if description:
        body_parts.append(f"Comentario: {description}")

    payload = {
        "sender": {
            "name": "Sistema Limpeza WC",
            "email": "mvita523@gmail.com"
        },
        "to": [{"email": email} for email in recipients],
        "subject": f"Novo reporte WC #{report_id}",
        "textContent": "\n".join(body_parts),
    }

    headers = {
        "accept": "application/json",
        "api-key": os.environ["BREVO_API_KEY"],
        "content-type": "application/json",
    }

    try:
        response = requests.post(
            BREVO_API_URL,
            json=payload,
            headers=headers,
            timeout=10,
        )

        response.raise_for_status()

        logger.info(
            "email_sent report_id=%s recipient_count=%s",
            report_id,
            len(recipients),
        )

        return True, ""

    except Exception:
        logger.exception("email_failed report_id=%s")
        return False, "Falha ao enviar email."
