import smtplib
from email.message import EmailMessage

from .config import DEFAULT_ADMIN_EMAIL, GMAIL_ADDRESS, GMAIL_APP_PASSWORD, logger
from .database import get_cleaner_notification_emails, get_setting
from .utils import ISSUE_LABELS


def get_notification_email():
    return get_setting("notification_email", DEFAULT_ADMIN_EMAIL).strip()


def get_notification_recipients():
    recipients = get_cleaner_notification_emails()
    fallback_email = get_notification_email()
    if not recipients and fallback_email:
        recipients.append(fallback_email)
    return recipients


def email_enabled():
    return bool(GMAIL_ADDRESS and GMAIL_APP_PASSWORD and get_notification_recipients())


def notify_admin_by_email(report_id, issue_type, location, description):
    recipients = get_notification_recipients()
    if not email_enabled():
        logger.info("email_disabled report_id=%s", report_id)
        return False, "Email nao configurado."

    body_parts = [
        f"Novo reporte WC #{report_id}",
        f"Problema: {ISSUE_LABELS[issue_type]}",
        f"Sala/WC: {location['id']}",
        f"Local: {location['name']} ({location['building']}, piso {location['floor']})",
    ]
    if description:
        body_parts.append(f"Comentario: {description}")

    message = EmailMessage()
    message["Subject"] = f"Novo reporte WC #{report_id}"
    message["From"] = GMAIL_ADDRESS
    message["To"] = ", ".join(recipients)
    message.set_content("\n".join(body_parts))

    try:
        with smtplib.SMTP("smtp-relay.brevo.com", 587, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            smtp.send_message(message)
        
        logger.info("email_sent report_id=%s recipient_count=%s", report_id, len(recipients))
        return True, ""
    
    except (smtplib.SMTPException, OSError):
        logger.exception("email_failed report_id=%s", report_id)
        return False, "Falha ao enviar email."
