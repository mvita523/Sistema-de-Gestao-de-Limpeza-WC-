import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import psycopg2

from . import auth, database, email_service
from .config import CLEANER_SESSION_DAYS, FORM_MAX_BYTES, STATIC_DIR, logger
from .utils import (
    ISSUE_LABELS,
    STATUS_LABELS,
    SubmissionRateLimiter,
    clean_text,
    day_key,
    escape,
    format_datetime,
    is_valid_email,
    is_valid_password,
    is_valid_student_number,
    is_valid_username,
    redirect_target,
    render_template,
)

rate_limiter = SubmissionRateLimiter()


class AppHandler(BaseHTTPRequestHandler):
    server_version = "WCCleaningPython/2.0"

    def end_headers(self):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
        if self.headers.get("X-Forwarded-Proto", "https") == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def log_message(self, fmt, *args):
        logger.info("request client=%s method=%s path=%s status=%s", self.client_address[0], self.command, self.path, fmt % args)

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
        if length > FORM_MAX_BYTES:
            raise ValueError("Form too large")
        raw = self.rfile.read(length).decode("utf-8")
        return {key: values[0] for key, values in parse_qs(raw, keep_blank_values=True).items()}

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > FORM_MAX_BYTES:
            raise ValueError("Payload too large")
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)

    def show_report(self, query, error=""):
        location_id = clean_text((query.get("location_id") or [""])[0], 20)
        selected_issue = clean_text((query.get("issue_type") or [""])[0], 20)
        description = clean_text((query.get("description") or [""])[0], 500, multiline=True)
        student_number = clean_text((query.get("student_number") or [""])[0], 40)
        location = database.get_location(int(location_id)) if location_id.isdigit() else None
        max_location_id = database.get_max_location_id()

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
            student_number=escape(student_number),
            location_html=location_html,
            issue_options="\n".join(issue_buttons),
            error_html=self.error_box(error),
        )
        return self.html_response(body)

    def create_report(self):
        try:
            form = self.read_form()
        except ValueError:
            return self.show_report({}, "Pedido demasiado grande.")

        location_id = clean_text(form.get("location_id", ""), 20)
        issue_type = clean_text(form.get("issue_type", ""), 20)
        description = clean_text(form.get("description", ""), 500, multiline=True)
        student_number = clean_text(form.get("student_number", ""), 40)
        max_location_id = database.get_max_location_id()

        if not location_id.isdigit() or int(location_id) <= 0:
            return self.show_report({"location_id": [location_id]}, "Indica um numero de WC valido.")
        if int(location_id) > max_location_id:
            return self.show_report({"location_id": [location_id]}, f"O numero do WC deve estar entre 1 e {max_location_id}.")
        if issue_type not in ISSUE_LABELS:
            return self.show_report({"location_id": [location_id]}, "Seleciona o tipo de problema.")
        if not is_valid_student_number(student_number):
            return self.show_report({"location_id": [location_id]}, "Indica um numero de estudante valido.")

        location = database.get_location(int(location_id))
        if not location:
            return self.show_report({"location_id": [location_id]}, "Localizacao nao encontrada.")

        if not rate_limiter.allow(self.client_address[0], location_id):
            return self.show_report(
                {"location_id": [location_id], "issue_type": [issue_type], "description": [description], "student_number": [student_number]},
                "Aguarde antes de enviar outro reporte para este WC.",
            )

        try:
            report_id = database.create_report(int(location_id), issue_type, description, student_number)
        except psycopg2.Error:
            logger.exception("report_create_failed")
            return self.show_report({"location_id": [location_id]}, "Nao foi possivel guardar o reporte.")

        logger.info("report_created report_id=%s issue_type=%s location_id=%s", report_id, issue_type, location_id)
        email_service.notify_admin_by_email(report_id, issue_type, location, description)
        return self.html_response(render_template("success.html"), HTTPStatus.CREATED)

    def show_admin(self, query):
        if not auth.valid_admin_cookie(self.headers):
            csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
            body = render_template("admin_login.html", error_html="", csrf_token=escape(csrf_token))
            return self.html_response(body, csrf_token=csrf_token if is_new else None)

        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        status = clean_text((query.get("status") or ["pending"])[0], 20)
        location_id = clean_text((query.get("location_id") or ["all"])[0], 20)
        reports = database.filtered_reports(status, location_id)
        locations = database.get_locations()
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            email_message=self.email_message((query.get("email") or [""])[0]),
            settings_message=self.settings_message((query.get("settings") or [""])[0]),
            users_message=self.users_message((query.get("users") or [""])[0]),
            notification_email=escape(email_service.get_notification_email()),
            cleaning_user_rows=self.cleaning_user_rows(cleaning_users=database.list_cleaning_users(), csrf_token=csrf_token),
            status_options=self.status_options(status),
            location_options=self.location_options(locations, location_id),
            report_rows=self.report_rows(reports, status, location_id, csrf_token),
            visible_count=len(reports),
            pending_count=sum(1 for report in reports if report["status"] == "pending"),
            resolved_count=sum(1 for report in reports if report["status"] == "resolved"),
            by_day_bars=self.bar_list(self.count_by_day(reports)),
            by_issue_bars=self.bar_list(self.count_by_issue(reports)),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def show_cleaner(self, query):
        cleaner = database.get_cleaner_by_session(auth.get_cleaner_session_token(self.headers))
        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        if not cleaner:
            error_status = (query.get("error") or [""])[0]
            body = render_template(
                "cleaner_login.html",
                csrf_token=escape(csrf_token),
                error_html=self.cleaner_login_error(error_status),
            )
            return self.html_response(body, csrf_token=csrf_token if is_new else None)

        reports = database.filtered_reports("pending", "all")
        body = render_template(
            "cleaner_dashboard.html",
            csrf_token=escape(csrf_token),
            cleaner_name=escape(cleaner["name"]),
            cleaner_username=escape(cleaner["username"]),
            cleaner_email=escape(cleaner["email"] or "Sem email associado"),
            report_rows=self.cleaner_report_rows(reports, csrf_token),
            pending_count=len(reports),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def login_admin(self):
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            logger.warning("auth_failure reason=csrf area=admin")
            return self.html_response(render_template("admin_login.html", error_html=self.error_box("Sessao expirada."), csrf_token=""), HTTPStatus.FORBIDDEN)
        if form.get("token", "") != auth.ADMIN_TOKEN:
            logger.warning("auth_failure reason=invalid_token area=admin")
            csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
            body = render_template("admin_login.html", error_html=self.error_box("Token de acesso invalido."), csrf_token=escape(csrf_token))
            return self.html_response(body, HTTPStatus.UNAUTHORIZED, csrf_token=csrf_token if is_new else None)
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/admin")
        self.set_cookie("admin_token", auth.create_admin_session_token(), max_age=auth.ADMIN_SESSION_SECONDS)
        self.end_headers()

    def logout_admin(self):
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_admin_cookie(self.headers) or not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/admin")
        self.clear_cookie("admin_token")
        self.end_headers()

    def create_cleaning_user_form(self):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin?users=csrf")

        name = clean_text(form.get("name", ""), 120)
        username = clean_text(form.get("username", ""), 40).lower()
        email = clean_text(form.get("email", ""), 180)
        password = form.get("password", "")

        if not name or not is_valid_username(username) or not is_valid_password(password) or (email and not is_valid_email(email)):
            return self.redirect("/admin?users=invalid")
        try:
            database.create_cleaning_user(name, username, email, password)
        except psycopg2.IntegrityError:
            return self.redirect("/admin?users=duplicate")
        logger.info("cleaning_user_created username=%s", username)
        return self.redirect("/admin?users=created")

    def update_cleaning_user_email_form(self, user_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin?users=csrf")
        email = clean_text(form.get("email", ""), 180)
        if email and not is_valid_email(email):
            return self.redirect("/admin?users=invalid-email")
        database.update_cleaning_user_email(user_id, email, form.get("receives_notifications") == "on")
        return self.redirect("/admin?users=updated")

    def delete_cleaning_user_form(self, user_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin?users=csrf")
        database.delete_cleaning_user(user_id)
        return self.redirect("/admin?users=deleted")

    def login_cleaner(self):
        form = self.safe_form_or_redirect("/cleaner")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            logger.warning("auth_failure reason=csrf area=cleaner")
            return self.redirect("/cleaner?error=invalid")
        username = clean_text(form.get("username", ""), 40).lower()
        password = form.get("password", "")
        if not is_valid_username(username):
            logger.warning("auth_failure reason=invalid_username area=cleaner")
            return self.redirect("/cleaner?error=invalid")
        user = database.find_cleaning_user(username)
        if not user or not user["active"] or not auth.verify_password(password, user["password_hash"]):
            logger.warning("auth_failure reason=bad_credentials area=cleaner username=%s", username)
            return self.redirect("/cleaner?error=invalid")
        token = database.create_cleaner_session(user["id"])
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/cleaner")
        self.set_cookie("cleaner_session", token, max_age=CLEANER_SESSION_DAYS * 24 * 60 * 60)
        self.end_headers()

    def logout_cleaner(self):
        form = self.safe_form_or_redirect("/cleaner")
        if form is None:
            return
        if auth.valid_csrf(self.headers, form):
            database.delete_cleaner_session(auth.get_cleaner_session_token(self.headers))
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/cleaner")
        self.clear_cookie("cleaner_session")
        self.end_headers()

    def update_notification_email_form(self):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin?settings=csrf")
        email = clean_text(form.get("notification_email", ""), 180)
        if not is_valid_email(email):
            return self.redirect("/admin?settings=invalid-email")
        database.set_setting("notification_email", email)
        return self.redirect("/admin?settings=saved")

    def get_notification_email_api(self):
        if not auth.valid_admin_bearer(self.headers):
            return self.json_response({"error": "Acesso admin invalido."}, HTTPStatus.UNAUTHORIZED)
        return self.json_response({"data": {"notification_email": email_service.get_notification_email()}})

    def update_notification_email_api(self):
        if not auth.valid_admin_bearer(self.headers):
            return self.json_response({"error": "Acesso admin invalido."}, HTTPStatus.UNAUTHORIZED)
        try:
            payload = self.read_json()
        except (json.JSONDecodeError, ValueError):
            return self.json_response({"error": "JSON invalido."}, HTTPStatus.BAD_REQUEST)
        email = clean_text(payload.get("notification_email", ""), 180)
        if not is_valid_email(email):
            return self.json_response({"error": "Email invalido."}, HTTPStatus.BAD_REQUEST)
        database.set_setting("notification_email", email)
        return self.json_response({"data": {"notification_email": email}})

    def resolve_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        database.resolve_report(report_id)
        return self.redirect(redirect_target("/admin", {"status": form.get("status", "pending"), "location_id": form.get("location_id", "all")}))

    def resolve_report_cleaner(self, report_id):
        cleaner = database.get_cleaner_by_session(auth.get_cleaner_session_token(self.headers))
        if not cleaner:
            return self.redirect("/cleaner")
        form = self.safe_form_or_redirect("/cleaner")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/cleaner")
        database.resolve_report(report_id, cleaner["id"])
        return self.redirect("/cleaner")

    def safe_form_or_redirect(self, location):
        try:
            return self.read_form()
        except ValueError:
            self.redirect(location)
            return None

    def email_message(self, status):
        if status == "failed":
            return '<div class="error">Falha ao enviar email. Ve os logs do servidor.</div>'
        return ""

    def settings_message(self, status):
        if status == "saved":
            return '<div class="success-box">Email de notificacao atualizado.</div>'
        if status == "invalid-email":
            return '<div class="error">Indica um email de notificacao valido.</div>'
        if status == "csrf":
            return '<div class="error">Sessao expirada. Tenta novamente.</div>'
        return ""

    def users_message(self, status):
        messages = {
            "created": '<div class="success-box">Utilizador de limpeza criado.</div>',
            "updated": '<div class="success-box">Email do utilizador de limpeza atualizado.</div>',
            "deleted": '<div class="success-box">Utilizador de limpeza eliminado.</div>',
            "invalid": '<div class="error">Preenche nome, utilizador valido e uma palavra-passe com pelo menos 8 caracteres.</div>',
            "invalid-email": '<div class="error">Indica um email valido para o utilizador de limpeza.</div>',
            "duplicate": '<div class="error">Esse nome de utilizador ja existe.</div>',
            "csrf": '<div class="error">Sessao expirada. Tenta novamente.</div>',
        }
        return messages.get(status, "")

    def cleaner_login_error(self, status):
        return '<div class="error">Credenciais invalidas.</div>' if status == "invalid" else ""

    def status_options(self, current):
        options = [("all", "Todos os estados"), ("pending", "Pendentes"), ("resolved", "Resolvidos")]
        return "\n".join(f'<option value="{value}" {"selected" if value == current else ""}>{label}</option>' for value, label in options)

    def location_options(self, locations, current):
        rows = ['<option value="all">Todas as localizacoes</option>']
        for location in locations:
            selected = "selected" if str(location["id"]) == current else ""
            label = f"Sala/WC {location['id']} - {location['name']} - {location['building']}"
            rows.append(f'<option value="{location["id"]}" {selected}>{escape(label)}</option>')
        return "\n".join(rows)

    def report_rows(self, reports, status, location_id, csrf_token):
        if not reports:
            return '<p class="empty">Nenhum reporte encontrado.</p>'
        rows = []
        for report in reports:
            description = f'<p class="description">{escape(report["description"])}</p>' if report["description"] else ""
            student_info = f'<p class="muted">N.º estudante: {escape(report["student_number"])}</p>' if report.get("student_number") else ""
            resolved_by_html = ""
            if report["status"] == "resolved":
                resolved_by_html = f'<p class="muted">Resolvido por: {escape(report.get("resolved_by_name") or "Administrador")}</p>'
            action = ""
            if report["status"] == "pending":
                action = (
                    f'<form method="post" action="/admin/reports/{report["id"]}/resolve">'
                    f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                    f'<input type="hidden" name="status" value="{escape(status)}">'
                    f'<input type="hidden" name="location_id" value="{escape(location_id)}">'
                    '<button class="button button-success" type="submit">Resolver</button>'
                    "</form>"
                )
            rows.append(
                '<article class="report-row"><div><div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(report["location_name"])}</h2>'
                f'<p class="room-number">Numero da sala/WC: {escape(report["location_id"])}</p>'
                f'<p class="muted">{escape(report["building"])}, piso {escape(report["floor"])} - {format_datetime(report["created_at"])}</p>'
                f"{student_info}{resolved_by_html}{description}</div>{action}</article>"
            )
        return "\n".join(rows)

    def cleaner_report_rows(self, reports, csrf_token):
        if not reports:
            return '<p class="empty">Nenhum reporte pendente.</p>'
        rows = []
        for report in reports:
            description = f'<p class="description">{escape(report["description"])}</p>' if report["description"] else ""
            student_info = f'<p class="muted">N.º estudante: {escape(report["student_number"])}</p>' if report.get("student_number") else ""
            rows.append(
                '<article class="report-row"><div><div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(report["location_name"])}</h2>'
                f'<p class="room-number">Numero da sala/WC: {escape(report["location_id"])}</p>'
                f'<p class="muted">{escape(report["building"])}, piso {escape(report["floor"])} - {format_datetime(report["created_at"])}</p>'
                f"{student_info}{description}</div>"
                f'<form method="post" action="/cleaner/reports/{report["id"]}/resolve">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '<button class="button button-success" type="submit">Marcar resolvido</button>'
                "</form></article>"
            )
        return "\n".join(rows)

    def cleaning_user_rows(self, cleaning_users, csrf_token):
        if not cleaning_users:
            return '<p class="empty">Nenhum utilizador de limpeza criado.</p>'
        rows = []
        for user in cleaning_users:
            checked = "checked" if user["receives_notifications"] else ""
            rows.append(
                '<article class="user-row"><div>'
                f'<strong>{escape(user["name"])}</strong><span>{escape(user["username"])}</span></div>'
                f'<form class="user-email-form" method="post" action="/admin/cleaning-users/{user["id"]}/email">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                f'<input type="email" name="email" value="{escape(user["email"] or "")}" placeholder="email@exemplo.com">'
                '<label class="check-field">'
                f'<input type="checkbox" name="receives_notifications" {checked}>'
                '<span>Recebe notificacoes</span></label>'
                '<button class="button button-secondary" type="submit">Guardar</button></form>'
                f'<form method="post" action="/admin/cleaning-users/{user["id"]}/delete">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '<button class="button button-danger" type="submit">Eliminar</button></form></article>'
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
        return "\n".join(
            '<div class="bar-row">'
            f'<div><strong>{escape(label)}</strong><span>{count}</span></div>'
            '<div class="bar-track">'
            f'<span class="bar-fill" style="width: {max(8, round((count / max_value) * 100))}%"></span>'
            "</div></div>"
            for label, count in values
        )

    def error_box(self, message):
        return f'<div class="error">{escape(message)}</div>' if message else ""

    def set_cookie(self, name, value, max_age=None):
        cookie = f"{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/"
        if max_age is not None:
            cookie += f"; Max-Age={int(max_age)}"
        self.send_header("Set-Cookie", cookie)

    def clear_cookie(self, name):
        self.send_header("Set-Cookie", f"{name}=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/")

    def static_file(self, path, content_type):
        if not path.exists():
            return self.not_found()
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def html_response(self, body, status=HTTPStatus.OK, csrf_token=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if csrf_token:
            self.set_cookie("csrf_token", csrf_token, max_age=auth.CSRF_TOKEN_SECONDS)
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
