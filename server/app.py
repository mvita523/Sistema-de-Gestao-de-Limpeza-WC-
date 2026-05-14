from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
from email.message import EmailMessage
import hashlib
import html
import hmac
import json
import os
import re
import secrets
import smtplib
import threading
import time

import psycopg2
from psycopg2.extras import RealDictCursor


BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

SPAM_WINDOW_SECONDS = 60
REPORT_RETENTION_DAYS = 15
CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60
CLEANER_SESSION_DAYS = 7

ISSUE_LABELS = {
    "paper": "Sem papel higienico",
    "soap": "Sem sabonete",
    "dirty": "WC sujo",
    "smell": "Mau cheiro",
    "other": "Outro",
}

STATUS_LABELS = {
    "pending": "Pendente",
    "resolved": "Resolvido",
}

recent_submissions = {}


def load_env_file():
    env_path = BASE_DIR / "server" / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me")
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:kimpa1017*#@db.gkxtnwmpatbaeqeulujk.supabase.co:5432/postgres",
)
PORT = int(os.environ.get("PORT", "10000"))
GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")
DEFAULT_ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")


def connect():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor,
        sslmode="require"
    )


def init_database():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA_PATH.read_text(encoding="utf-8"))


def cleanup_old_reports():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM reports
                WHERE created_at < NOW() - (%s * INTERVAL '1 day')
                """,
                (REPORT_RETENTION_DAYS,),
            )
            deleted_count = cursor.rowcount
            cursor.execute("DELETE FROM cleaning_sessions WHERE expires_at < NOW()")

    if deleted_count:
        print(f"[LIMPEZA BD] {deleted_count} reportes com mais de {REPORT_RETENTION_DAYS} dias eliminados.")


def start_cleanup_scheduler():
    def run_cleanup_loop():
        while True:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                cleanup_old_reports()
            except Exception as error:
                print(f"[LIMPEZA BD] Falha na limpeza automatica: {error}")

    thread = threading.Thread(target=run_cleanup_loop, daemon=True)
    thread.start()


def render_template(name, **context):
    content = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    for key, value in context.items():
        content = content.replace("{{ " + key + " }}", str(value))
    return content


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def format_datetime(value):
    if not value:
        return ""
    value = str(value)
    return value.replace("T", " ")[:16]


def day_key(value):
    if not value:
        return ""
    value = str(value)
    date_part = value[:10]
    parts = date_part.split("-")
    if len(parts) == 3:
        return f"{parts[2]}/{parts[1]}"
    return date_part


def get_locations():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, building, floor, created_at
                FROM locations
                ORDER BY building ASC, floor ASC, name ASC
                """
            )
            return cursor.fetchall()


def hash_password(password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${password_hash.hex()}"


def verify_password(password, stored_hash):
    try:
        algorithm, salt, expected_hash = stored_hash.split("$", 2)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return hmac.compare_digest(actual_hash.hex(), expected_hash)


def list_cleaning_users():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, username, email, receives_notifications, active, created_at
                FROM cleaning_users
                ORDER BY created_at DESC
                """
            )
            return cursor.fetchall()


def create_cleaning_user(name, username, email, password):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO cleaning_users (name, username, email, password_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (name, username, email, hash_password(password)),
            )


def update_cleaning_user_email(user_id, email, receives_notifications):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE cleaning_users
                SET email = %s, receives_notifications = %s
                WHERE id = %s
                """,
                (email, receives_notifications, user_id),
            )


def delete_cleaning_user(user_id):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM cleaning_users WHERE id = %s", (user_id,))


def find_cleaning_user(username):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, username, password_hash, active
                FROM cleaning_users
                WHERE username = %s
                """,
                (username,),
            )
            return cursor.fetchone()


def create_cleaner_session(user_id):
    token = secrets.token_urlsafe(48)
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO cleaning_sessions (token, user_id, expires_at)
                VALUES (%s, %s, NOW() + (%s * INTERVAL '1 day'))
                """,
                (token, user_id, CLEANER_SESSION_DAYS),
            )
    return token


def get_cleaner_by_session(token):
    if not token:
        return None

    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT u.id, u.name, u.username
                FROM cleaning_sessions s
                JOIN cleaning_users u ON u.id = s.user_id
                WHERE s.token = %s AND s.expires_at > NOW() AND u.active = TRUE
                """,
                (token,),
            )
            return cursor.fetchone()


def delete_cleaner_session(token):
    if not token:
        return

    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM cleaning_sessions WHERE token = %s", (token,))


def get_location(location_id):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, name, building, floor FROM locations WHERE id = %s",
                (location_id,),
            )
            return cursor.fetchone()


def get_max_location_id():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COALESCE(MAX(id), 1) AS max_id FROM locations")
            return cursor.fetchone()["max_id"]


def get_setting(key, default_value=""):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT value FROM app_settings WHERE key = %s", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default_value


def set_setting(key, value):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key)
                DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (key, value),
            )


def get_notification_email():
    return get_setting("notification_email", DEFAULT_ADMIN_EMAIL).strip()


def get_cleaner_notification_emails():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT email
                FROM cleaning_users
                WHERE active = TRUE
                  AND receives_notifications = TRUE
                  AND email IS NOT NULL
                  AND email <> ''
                ORDER BY name ASC
                """
            )
            return [row["email"].strip() for row in cursor.fetchall() if row["email"].strip()]


def get_notification_recipients():
    recipients = get_cleaner_notification_emails()
    fallback_email = get_notification_email()

    if not recipients and fallback_email:
        recipients.append(fallback_email)

    return recipients


def is_valid_email(value):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value.strip()))


def email_enabled():
    return bool(GMAIL_ADDRESS.strip() and GMAIL_APP_PASSWORD.strip() and get_notification_recipients())


def notify_admin_by_email(report_id, issue_type, location, description):
    recipients = get_notification_recipients()

    if not email_enabled():
        print(
            "[EMAIL ADMIN] Notificacao desativada: configura GMAIL_ADDRESS, "
            "GMAIL_APP_PASSWORD e pelo menos um destinatario de notificacao."
        )
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
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as smtp:
            smtp.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            smtp.send_message(message)
        print(f"[EMAIL ADMIN] Notificacao enviada para {', '.join(recipients)}")
        return True, ""
    except (smtplib.SMTPException, OSError) as error:
        print(f"[EMAIL ADMIN] Falha ao enviar notificacao: {error}")
        return False, str(error)


def valid_admin_cookie(headers):
    cookie_header = headers.get("Cookie", "")
    cookies = SimpleCookie(cookie_header)
    morsel = cookies.get("admin_token")
    return bool(morsel and morsel.value == ADMIN_TOKEN)


def get_cleaner_session_token(headers):
    cookie_header = headers.get("Cookie", "")
    cookies = SimpleCookie(cookie_header)
    morsel = cookies.get("cleaner_session")
    return morsel.value if morsel else ""


def valid_admin_bearer(headers):
    auth_header = headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    return bool(token and token == ADMIN_TOKEN)


def redirect_target(path, params=None):
    query = urlencode(params or {})
    return path + (f"?{query}" if query else "")


class AppHandler(BaseHTTPRequestHandler):
    server_version = "WCCleaningPython/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            return self.json_response({"ok": True})
        if parsed.path == "/":
            return self.redirect("/report")
        if parsed.path == "/report":
            return self.show_report(parse_qs(parsed.query))
        if parsed.path == "/admin":
            return self.show_admin(parse_qs(parsed.query))
        if parsed.path == "/cleaner":
            return self.show_cleaner(parse_qs(parsed.query))
        if parsed.path == "/api/admin/notification-email":
            return self.get_notification_email_api()
        if parsed.path == "/static/styles.css":
            return self.static_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")

        return self.not_found()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/report":
            return self.create_report()
        if parsed.path == "/admin/login":
            return self.login_admin()
        if parsed.path == "/admin/logout":
            return self.logout_admin()
        if parsed.path == "/admin/notification-email":
            return self.update_notification_email_form()
        if parsed.path == "/admin/cleaning-users":
            return self.create_cleaning_user_form()
        if parsed.path == "/cleaner/login":
            return self.login_cleaner()
        if parsed.path == "/cleaner/logout":
            return self.logout_cleaner()

        match = re.fullmatch(r"/admin/reports/(\d+)/resolve", parsed.path)
        if match:
            return self.resolve_report(int(match.group(1)))
        match = re.fullmatch(r"/admin/cleaning-users/(\d+)/delete", parsed.path)
        if match:
            return self.delete_cleaning_user_form(int(match.group(1)))
        match = re.fullmatch(r"/admin/cleaning-users/(\d+)/email", parsed.path)
        if match:
            return self.update_cleaning_user_email_form(int(match.group(1)))
        match = re.fullmatch(r"/cleaner/reports/(\d+)/resolve", parsed.path)
        if match:
            return self.resolve_report_cleaner(int(match.group(1)))

        return self.not_found()

    def do_PATCH(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/admin/notification-email":
            return self.update_notification_email_api()

        return self.not_found()

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return {key: values[0] for key, values in parse_qs(raw).items()}

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)

    def show_report(self, query, error="", success=False):
        location_id = (query.get("location_id") or [""])[0]
        selected_issue = (query.get("issue_type") or [""])[0]
        description = (query.get("description") or [""])[0]
        location = get_location(int(location_id)) if location_id.isdigit() else None
        max_location_id = get_max_location_id()

        location_html = ""
        if location:
            location_html = (
                '<section class="notice">'
                f"<strong>{escape(location['name'])}</strong>"
                f"<span>Numero da sala/WC: {escape(location['id'])}</span>"
                f"<span>{escape(location['building'])}, piso {escape(location['floor'])}</span>"
                "</section>"
            )

        issue_buttons = []
        for issue_id, label in ISSUE_LABELS.items():
            checked = "checked" if selected_issue == issue_id else ""
            issue_buttons.append(
                '<label class="issue-option">'
                f'<input type="radio" name="issue_type" value="{issue_id}" {checked} required>'
                f"<span>{escape(label)}</span>"
                "</label>"
            )

        body = render_template(
            "report.html",
            location_id=escape(location_id),
            max_location_id=escape(max_location_id),
            description=escape(description),
            location_html=location_html,
            issue_options="\n".join(issue_buttons),
            error_html=self.error_box(error),
        )
        return self.html_response(body)

    def create_report(self):
        form = self.read_form()
        location_id = form.get("location_id", "").strip()
        issue_type = form.get("issue_type", "").strip()
        description = form.get("description", "").strip()[:500]
        max_location_id = get_max_location_id()

        if not location_id.isdigit() or int(location_id) <= 0:
            return self.show_report({"location_id": [location_id]}, "Indica um numero de WC valido.")
        if int(location_id) > max_location_id:
            return self.show_report(
                {"location_id": [location_id]},
                f"O numero do WC deve estar entre 1 e {max_location_id}.",
            )
        if issue_type not in ISSUE_LABELS:
            return self.show_report({"location_id": [location_id]}, "Seleciona o tipo de problema.")

        location = get_location(int(location_id))
        if not location:
            return self.show_report({"location_id": [location_id]}, "Localizacao nao encontrada.")

        spam_key = f"{self.client_address[0]}:{location_id}"
        last_submission = recent_submissions.get(spam_key, 0)
        if time.time() - last_submission < SPAM_WINDOW_SECONDS:
            return self.show_report(
                {"location_id": [location_id], "issue_type": [issue_type], "description": [description]},
                "Aguarde antes de enviar outro reporte para este WC.",
            )

        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO reports (location_id, issue_type, description)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (int(location_id), issue_type, description),
                )
                report_id = cursor.fetchone()["id"]

        recent_submissions[spam_key] = time.time()
        print(f"[NOTIFICACAO LIMPEZA] Novo reporte #{report_id}: {issue_type} em {location['name']}")
        notify_admin_by_email(report_id, issue_type, location, description)

        body = render_template("success.html")
        return self.html_response(body, HTTPStatus.CREATED)

    def show_admin(self, query):
        if not valid_admin_cookie(self.headers):
            return self.html_response(render_template("admin_login.html", error_html=""))

        status = (query.get("status") or ["pending"])[0]
        location_id = (query.get("location_id") or ["all"])[0]
        email_status = (query.get("email") or [""])[0]
        settings_status = (query.get("settings") or [""])[0]
        users_status = (query.get("users") or [""])[0]
        reports = self.filtered_reports(status, location_id)
        locations = get_locations()
        notification_email = get_notification_email()
        cleaning_users = list_cleaning_users()

        body = render_template(
            "admin.html",
            email_message=self.email_message(email_status),
            settings_message=self.settings_message(settings_status),
            users_message=self.users_message(users_status),
            notification_email=escape(notification_email),
            cleaning_user_rows=self.cleaning_user_rows(cleaning_users),
            status_options=self.status_options(status),
            location_options=self.location_options(locations, location_id),
            report_rows=self.report_rows(reports, status, location_id),
            visible_count=len(reports),
            pending_count=sum(1 for report in reports if report["status"] == "pending"),
            resolved_count=sum(1 for report in reports if report["status"] == "resolved"),
            by_day_bars=self.bar_list(self.count_by_day(reports)),
            by_issue_bars=self.bar_list(self.count_by_issue(reports)),
        )
        return self.html_response(body)

    def show_cleaner(self, query):
        cleaner = get_cleaner_by_session(get_cleaner_session_token(self.headers))
        if not cleaner:
            error_status = (query.get("error") or [""])[0]
            return self.html_response(
                render_template("cleaner_login.html", error_html=self.cleaner_login_error(error_status))
            )

        reports = self.filtered_reports("pending", "all")
        body = render_template(
            "cleaner_dashboard.html",
            cleaner_name=escape(cleaner["name"]),
            report_rows=self.cleaner_report_rows(reports),
            pending_count=len(reports),
        )
        return self.html_response(body)

    def filtered_reports(self, status, location_id):
        values = []
        where = []

        if status in STATUS_LABELS:
            where.append("r.status = %s")
            values.append(status)
        if location_id.isdigit():
            where.append("r.location_id = %s")
            values.append(int(location_id))

        where_sql = "WHERE " + " AND ".join(where) if where else ""
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT r.id, r.location_id, r.issue_type, r.description, r.status,
                           r.created_at, r.resolved_at, l.name AS location_name,
                           l.building, l.floor
                    FROM reports r
                    JOIN locations l ON l.id = r.location_id
                    {where_sql}
                    ORDER BY r.created_at DESC
                    """,
                    values,
                )
                return cursor.fetchall()

    def login_admin(self):
        form = self.read_form()
        token = form.get("token", "")
        if token != ADMIN_TOKEN:
            body = render_template(
                "admin_login.html",
                error_html=self.error_box("Token de acesso invalido."),
            )
            return self.html_response(body, HTTPStatus.UNAUTHORIZED)

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/admin")
        self.send_header("Set-Cookie", f"admin_token={ADMIN_TOKEN}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def logout_admin(self):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/admin")
        self.send_header("Set-Cookie", "admin_token=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def create_cleaning_user_form(self):
        if not valid_admin_cookie(self.headers):
            return self.redirect("/admin")

        form = self.read_form()
        name = form.get("name", "").strip()
        username = form.get("username", "").strip().lower()
        email = form.get("email", "").strip()
        password = form.get("password", "")

        if not name or not username or len(password) < 6 or (email and not is_valid_email(email)):
            return self.redirect("/admin?users=invalid")

        try:
            create_cleaning_user(name, username, email, password)
        except psycopg2.IntegrityError:
            return self.redirect("/admin?users=duplicate")

        return self.redirect("/admin?users=created")

    def update_cleaning_user_email_form(self, user_id):
        if not valid_admin_cookie(self.headers):
            return self.redirect("/admin")

        form = self.read_form()
        email = form.get("email", "").strip()
        receives_notifications = form.get("receives_notifications") == "on"

        if email and not is_valid_email(email):
            return self.redirect("/admin?users=invalid-email")

        update_cleaning_user_email(user_id, email, receives_notifications)
        return self.redirect("/admin?users=updated")

    def delete_cleaning_user_form(self, user_id):
        if not valid_admin_cookie(self.headers):
            return self.redirect("/admin")

        delete_cleaning_user(user_id)
        return self.redirect("/admin?users=deleted")

    def login_cleaner(self):
        form = self.read_form()
        username = form.get("username", "").strip().lower()
        password = form.get("password", "")
        user = find_cleaning_user(username)

        if not user or not user["active"] or not verify_password(password, user["password_hash"]):
            return self.redirect("/cleaner?error=invalid")

        token = create_cleaner_session(user["id"])
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/cleaner")
        self.send_header(
            "Set-Cookie",
            f"cleaner_session={token}; HttpOnly; SameSite=Lax; Path=/",
        )
        self.end_headers()

    def logout_cleaner(self):
        delete_cleaner_session(get_cleaner_session_token(self.headers))
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/cleaner")
        self.send_header("Set-Cookie", "cleaner_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def update_notification_email_form(self):
        if not valid_admin_cookie(self.headers):
            return self.redirect("/admin")

        form = self.read_form()
        email = form.get("notification_email", "").strip()

        if not is_valid_email(email):
            return self.redirect("/admin?settings=invalid-email")

        set_setting("notification_email", email)
        return self.redirect("/admin?settings=saved")

    def get_notification_email_api(self):
        if not valid_admin_bearer(self.headers):
            return self.json_response({"error": "Acesso admin invalido."}, HTTPStatus.UNAUTHORIZED)

        return self.json_response({"data": {"notification_email": get_notification_email()}})

    def update_notification_email_api(self):
        if not valid_admin_bearer(self.headers):
            return self.json_response({"error": "Acesso admin invalido."}, HTTPStatus.UNAUTHORIZED)

        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            return self.json_response({"error": "JSON invalido."}, HTTPStatus.BAD_REQUEST)

        email = str(payload.get("notification_email", "")).strip()
        if not is_valid_email(email):
            return self.json_response({"error": "Email invalido."}, HTTPStatus.BAD_REQUEST)

        set_setting("notification_email", email)
        return self.json_response({"data": {"notification_email": email}})

    def resolve_report(self, report_id):
        if not valid_admin_cookie(self.headers):
            return self.redirect("/admin")

        form = self.read_form()
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE reports
                    SET status = 'resolved', resolved_at = COALESCE(resolved_at, NOW())
                    WHERE id = %s
                    """,
                    (report_id,),
                )

        return self.redirect(
            redirect_target(
                "/admin",
                {
                    "status": form.get("status", "pending"),
                    "location_id": form.get("location_id", "all"),
                },
            )
        )

    def resolve_report_cleaner(self, report_id):
        if not get_cleaner_by_session(get_cleaner_session_token(self.headers)):
            return self.redirect("/cleaner")

        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE reports
                    SET status = 'resolved', resolved_at = COALESCE(resolved_at, NOW())
                    WHERE id = %s
                    """,
                    (report_id,),
                )

        return self.redirect("/cleaner")

    def email_message(self, status):
        if status == "failed":
            return '<div class="error">Falha ao enviar email. Ve o erro no terminal do servidor.</div>'
        return ""

    def settings_message(self, status):
        if status == "saved":
            return '<div class="success-box">Email de notificacao atualizado.</div>'
        if status == "invalid-email":
            return '<div class="error">Indica um email de notificacao valido.</div>'
        return ""

    def users_message(self, status):
        messages = {
            "created": '<div class="success-box">Utilizador de limpeza criado.</div>',
            "updated": '<div class="success-box">Email do utilizador de limpeza atualizado.</div>',
            "deleted": '<div class="success-box">Utilizador de limpeza eliminado.</div>',
            "invalid": '<div class="error">Preenche nome, utilizador e uma palavra-passe com pelo menos 6 caracteres.</div>',
            "invalid-email": '<div class="error">Indica um email valido para o utilizador de limpeza.</div>',
            "duplicate": '<div class="error">Esse nome de utilizador ja existe.</div>',
        }
        return messages.get(status, "")

    def cleaner_login_error(self, status):
        if status == "invalid":
            return '<div class="error">Credenciais invalidas.</div>'
        return ""

    def status_options(self, current):
        options = [("all", "Todos os estados"), ("pending", "Pendentes"), ("resolved", "Resolvidos")]
        return "\n".join(
            f'<option value="{value}" {"selected" if value == current else ""}>{label}</option>'
            for value, label in options
        )

    def location_options(self, locations, current):
        rows = ['<option value="all">Todas as localizacoes</option>']
        for location in locations:
            selected = "selected" if str(location["id"]) == current else ""
            label = f"Sala/WC {location['id']} - {location['name']} - {location['building']}"
            rows.append(f'<option value="{location["id"]}" {selected}>{escape(label)}</option>')
        return "\n".join(rows)

    def report_rows(self, reports, status, location_id):
        if not reports:
            return '<p class="empty">Nenhum reporte encontrado.</p>'

        rows = []
        for report in reports:
            description = ""
            if report["description"]:
                description = f'<p class="description">{escape(report["description"])}</p>'

            action = ""
            if report["status"] == "pending":
                action = (
                    f'<form method="post" action="/admin/reports/{report["id"]}/resolve">'
                    f'<input type="hidden" name="status" value="{escape(status)}">'
                    f'<input type="hidden" name="location_id" value="{escape(location_id)}">'
                    '<button class="button button-success" type="submit">Resolver</button>'
                    "</form>"
                )

            rows.append(
                '<article class="report-row">'
                "<div>"
                '<div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(report["location_name"])}</h2>'
                f'<p class="room-number">Numero da sala/WC: {escape(report["location_id"])}</p>'
                f'<p class="muted">{escape(report["building"])}, piso {escape(report["floor"])} - {format_datetime(report["created_at"])}</p>'
                f"{description}"
                "</div>"
                f"{action}"
                "</article>"
            )
        return "\n".join(rows)

    def cleaner_report_rows(self, reports):
        if not reports:
            return '<p class="empty">Nenhum reporte pendente.</p>'

        rows = []
        for report in reports:
            description = ""
            if report["description"]:
                description = f'<p class="description">{escape(report["description"])}</p>'

            rows.append(
                '<article class="report-row">'
                "<div>"
                '<div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(report["location_name"])}</h2>'
                f'<p class="room-number">Numero da sala/WC: {escape(report["location_id"])}</p>'
                f'<p class="muted">{escape(report["building"])}, piso {escape(report["floor"])} - {format_datetime(report["created_at"])}</p>'
                f"{description}"
                "</div>"
                f'<form method="post" action="/cleaner/reports/{report["id"]}/resolve">'
                '<button class="button button-success" type="submit">Marcar resolvido</button>'
                "</form>"
                "</article>"
            )
        return "\n".join(rows)

    def cleaning_user_rows(self, users):
        if not users:
            return '<p class="empty">Nenhum utilizador de limpeza criado.</p>'

        rows = []
        for user in users:
            checked = "checked" if user["receives_notifications"] else ""
            rows.append(
                '<article class="user-row">'
                "<div>"
                f'<strong>{escape(user["name"])}</strong>'
                f'<span>{escape(user["username"])}</span>'
                "</div>"
                f'<form class="user-email-form" method="post" action="/admin/cleaning-users/{user["id"]}/email">'
                f'<input type="email" name="email" value="{escape(user["email"] or "")}" placeholder="email@exemplo.com">'
                '<label class="check-field">'
                f'<input type="checkbox" name="receives_notifications" {checked}>'
                '<span>Recebe notificacoes</span>'
                "</label>"
                '<button class="button button-secondary" type="submit">Guardar</button>'
                "</form>"
                f'<form method="post" action="/admin/cleaning-users/{user["id"]}/delete">'
                '<button class="button button-danger" type="submit">Eliminar</button>'
                "</form>"
                "</article>"
            )
        return "\n".join(rows)

    def count_by_day(self, reports):
        counts = {}
        for report in reports:
            key = day_key(report["created_at"])
            counts[key] = counts.get(key, 0) + 1
        return list(counts.items())[:7]

    def count_by_issue(self, reports):
        counts = {}
        for report in reports:
            key = ISSUE_LABELS[report["issue_type"]]
            counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)

    def bar_list(self, values):
        if not values:
            return '<p class="muted">Sem dados para mostrar.</p>'
        max_value = max(count for _, count in values)
        rows = []
        for label, count in values:
            width = max(8, round((count / max_value) * 100))
            rows.append(
                '<div class="bar-row">'
                f'<div><strong>{escape(label)}</strong><span>{count}</span></div>'
                '<div class="bar-track">'
                f'<span class="bar-fill" style="width: {width}%"></span>'
                "</div>"
                "</div>"
            )
        return "\n".join(rows)

    def error_box(self, message):
        if not message:
            return ""
        return f'<div class="error">{escape(message)}</div>'

    def static_file(self, path, content_type):
        if not path.exists():
            return self.not_found()
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def html_response(self, body, status=HTTPStatus.OK):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def json_response(self, payload, status=HTTPStatus.OK):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def not_found(self):
        self.html_response("<h1>Pagina nao encontrada</h1>", HTTPStatus.NOT_FOUND)


def main():
    init_database()
    cleanup_old_reports()
    start_cleanup_scheduler()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), AppHandler)
    print(f"Sistema WC a correr em http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
