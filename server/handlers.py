import json
import re
import secrets
from email.parser import BytesParser
from email.policy import default as email_policy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import psycopg2

from . import auth, database, email_service
from .config import CLEANER_SESSION_DAYS, FORM_MAX_BYTES, STATIC_DIR, UPLOAD_DIR, UPLOAD_MAX_BYTES, logger
from .utils import (
    ALLOWED_IMAGE_EXTENSIONS,
    ALLOWED_IMAGE_TYPES,
    COURSE_OPTIONS,
    ISSUE_LABELS,
    LOCAL_CATEGORY_LABELS,
    LOCAL_SUBCATEGORY_OPTIONS,
    PERIOD_LABELS,
    STATUS_LABELS,
    USER_CATEGORY_LABELS,
    SubmissionRateLimiter,
    clean_text,
    day_key,
    escape,
    format_datetime,
    is_valid_email,
    is_valid_password,
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
        if parsed.path.startswith("/static/uploads/"):
            return self.uploaded_file(parsed.path)
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
        match = re.fullmatch(r"/admin/reports/(\d+)/cancel", parsed.path)
        if match:
            return self.cancel_report(int(match.group(1)))
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

    def read_multipart_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        content_type = self.headers.get("Content-Type", "")
        if length > FORM_MAX_BYTES:
            raise ValueError("Form too large")
        if not content_type.startswith("multipart/form-data"):
            raise ValueError("Multipart form expected")

        raw_body = self.rfile.read(length)
        raw_message = (
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {length}\r\n"
            "MIME-Version: 1.0\r\n\r\n"
        ).encode("utf-8") + raw_body
        message = BytesParser(policy=email_policy).parsebytes(raw_message)
        if not message.is_multipart():
            raise ValueError("Multipart form expected")

        fields = {}
        files = {}
        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename:
                files[name] = {
                    "filename": filename,
                    "content_type": (part.get_content_type() or "").lower(),
                    "data": payload,
                }
            else:
                charset = part.get_content_charset() or "utf-8"
                fields[name] = payload.decode(charset, errors="replace")
        return fields, files

    def save_uploaded_image(self, files, field_name):
        item = files.get(field_name)
        if item is None or not item.get("filename"):
            raise ValueError("missing")

        extension = Path(item["filename"]).suffix.lower().lstrip(".")
        content_type = (item.get("content_type") or "").split(";")[0].strip().lower()
        if extension not in ALLOWED_IMAGE_EXTENSIONS or content_type not in ALLOWED_IMAGE_TYPES:
            raise ValueError("invalid_type")

        data = item.get("data") or b""
        if not data:
            raise ValueError("missing")
        if len(data) > UPLOAD_MAX_BYTES:
            raise ValueError("too_large")

        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{secrets.token_urlsafe(18)}.{extension}"
        target = UPLOAD_DIR / filename
        with target.open("wb") as file:
            file.write(data)
        return f"/static/uploads/{filename}"

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > FORM_MAX_BYTES:
            raise ValueError("Payload too large")
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)

    def show_report(self, query, error=""):
        selected_issue = clean_text((query.get("issue_type") or [""])[0], 20)
        description = clean_text((query.get("description") or [""])[0], 500, multiline=True)
        categoria_utilizador = clean_text((query.get("categoria_utilizador") or [""])[0], 40)
        categoria_local = clean_text((query.get("categoria_local") or [""])[0], 40)
        subcategoria_local = clean_text((query.get("subcategoria_local") or [""])[0], 160)
        curso = clean_text((query.get("curso") or [""])[0], 120)
        periodo = clean_text((query.get("periodo") or [""])[0], 40)

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
            description=escape(description),
            issue_options="\n".join(issue_buttons),
            user_category_options=self.option_tags(USER_CATEGORY_LABELS.items(), categoria_utilizador),
            local_category_options=self.option_tags(LOCAL_CATEGORY_LABELS.items(), categoria_local),
            subcategoria_local=escape(subcategoria_local),
            local_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            course_options=self.option_tags(((value, value) for value in COURSE_OPTIONS), curso),
            period_options=self.option_tags(PERIOD_LABELS.items(), periodo),
            error_html=self.error_box(error),
        )
        return self.html_response(body)

    def create_report(self):
        try:
            form, files = self.read_multipart_form()
        except ValueError:
            return self.show_report({}, "Pedido demasiado grande ou formulario invalido.")

        issue_type = clean_text(form.get("issue_type", ""), 20)
        description = clean_text(form.get("description", ""), 500, multiline=True)
        categoria_utilizador = clean_text(form.get("categoria_utilizador", ""), 40)
        categoria_local = clean_text(form.get("categoria_local", ""), 40)
        subcategoria_local = clean_text(form.get("subcategoria_local", ""), 160)
        curso = clean_text(form.get("curso", ""), 120)
        periodo = clean_text(form.get("periodo", ""), 40)
        query = {key: [value] for key, value in form.items()}

        if categoria_utilizador not in USER_CATEGORY_LABELS:
            return self.show_report(query, "Seleciona a categoria do utilizador.")
        if categoria_local not in LOCAL_CATEGORY_LABELS:
            return self.show_report(query, "Seleciona a categoria do local.")
        if subcategoria_local not in LOCAL_SUBCATEGORY_OPTIONS.get(categoria_local, []):
            return self.show_report(query, "Seleciona um local valido para a categoria escolhida.")
        if issue_type not in ISSUE_LABELS:
            return self.show_report(query, "Seleciona o tipo de problema.")
        if curso not in COURSE_OPTIONS:
            return self.show_report(query, "Seleciona um curso valido.")
        if periodo not in PERIOD_LABELS:
            return self.show_report(query, "Seleciona o periodo.")

        if not rate_limiter.allow(self.client_address[0], subcategoria_local):
            return self.show_report(
                query,
                "Aguarde antes de enviar outro reporte para este local.",
            )

        try:
            foto_reporte = self.save_uploaded_image(files, "foto_reporte")
        except ValueError as exc:
            message = "Anexa uma foto valida em JPG, PNG ou WEBP."
            if str(exc) == "too_large":
                message = "A foto deve ter no maximo 5 MB."
            return self.show_report(query, message)

        try:
            report_id = database.create_report(
                issue_type,
                description,
                categoria_utilizador,
                foto_reporte,
                categoria_local,
                subcategoria_local,
                curso,
                periodo,
            )
        except psycopg2.Error:
            logger.exception("report_create_failed")
            return self.show_report(query, "Nao foi possivel guardar o reporte.")

        logger.info("report_created report_id=%s issue_type=%s categoria_local=%s", report_id, issue_type, categoria_local)
        email_service.notify_admin_by_email(
            report_id,
            issue_type,
            {"name": subcategoria_local, "building": LOCAL_CATEGORY_LABELS[categoria_local], "floor": periodo, "id": "-"},
            description,
        )
        return self.html_response(render_template("success.html"), HTTPStatus.CREATED)

    def show_admin(self, query):
        if not auth.valid_admin_cookie(self.headers):
            csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
            body = render_template("admin_login.html", error_html="", csrf_token=escape(csrf_token))
            return self.html_response(body, csrf_token=csrf_token if is_new else None)

        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        status = clean_text((query.get("status") or ["pending"])[0], 20)
        location_id = clean_text((query.get("location_id") or ["all"])[0], 20)
        categoria_local = clean_text((query.get("categoria_local") or ["all"])[0], 20)
        periodo = clean_text((query.get("periodo") or ["all"])[0], 20)
        cleaner_name = clean_text((query.get("cleaner_name") or [""])[0], 120)
        user_search = clean_text((query.get("user_search") or [""])[0], 120)
        reports = database.filtered_reports(status, location_id, categoria_local=categoria_local if categoria_local != "all" else None, periodo=periodo if periodo != "all" else None, resolved_by_name=cleaner_name or None)
        all_reports = database.filtered_reports("all", "all")
        cleaning_users = database.list_cleaning_users()
        if user_search:
            cleaning_users = [u for u in cleaning_users if user_search.lower() in u["name"].lower()]
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            email_message=self.email_message((query.get("email") or [""])[0]),
            settings_message=self.settings_message((query.get("settings") or [""])[0]),
            users_message=self.users_message((query.get("users") or [""])[0]),
            notification_email=escape(email_service.get_notification_email()),
            cleaning_user_rows=self.cleaning_user_rows(cleaning_users=cleaning_users, csrf_token=csrf_token),
            status_options=self.status_options(status),
            category_options=self.category_options(categoria_local),
            periodo_options=self.period_options(periodo),
            subcategory_options=self.subcategory_options(categoria_local, ""),
            subcategory_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            report_rows=self.report_rows(reports, status, location_id, periodo, csrf_token),
            visible_count=len(reports),
            pending_count=sum(1 for report in all_reports if report["status"] == "pending"),
            resolved_count=sum(1 for report in all_reports if report["status"] == "resolved"),
            false_alert_count=sum(1 for report in all_reports if report.get("falso_alerta")),
            top_cleaners_html=self.top_cleaners_html(all_reports),
            top_course=escape(self.top_course(all_reports)),
            cleaner_name_query=escape(cleaner_name),
            user_search_query=escape(user_search),
            chart_payload=json.dumps(
                {
                    "byDay": self.chart_rows(self.count_by_day(all_reports)),
                    "byIssue": self.chart_rows(self.count_by_issue(all_reports)),
                    "byCategory": self.chart_rows(self.count_by_category(all_reports)),
                }
            ),
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
        resolved_count = database.count_resolved_by_cleaner(cleaner["id"])
        body = render_template(
            "cleaner_dashboard.html",
            csrf_token=escape(csrf_token),
            cleaner_name=escape(cleaner["name"]),
            cleaner_username=escape(cleaner["username"]),
            cleaner_email=escape(cleaner["email"] or "Sem email associado"),
            report_rows=self.cleaner_report_rows(reports, csrf_token),
            pending_count=len(reports),
            resolved_count=resolved_count,
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
        return self.redirect(redirect_target("/admin", {"status": form.get("status", "pending"), "categoria_local": form.get("categoria_local", "all"), "periodo": form.get("periodo", "all")}))

    def cancel_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        database.cancel_report(report_id)
        return self.redirect(redirect_target("/admin", {"status": form.get("status", "pending"), "categoria_local": form.get("categoria_local", "all"), "periodo": form.get("periodo", "all")}))

    def resolve_report_cleaner(self, report_id):
        cleaner = database.get_cleaner_by_session(auth.get_cleaner_session_token(self.headers))
        if not cleaner:
            return self.redirect("/cleaner")
        try:
            form, files = self.read_multipart_form()
        except ValueError:
            return self.redirect("/cleaner")
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/cleaner")
        try:
            foto_resolucao = self.save_uploaded_image(files, "foto_resolucao")
        except ValueError:
            return self.redirect("/cleaner")
        database.resolve_report(report_id, cleaner["id"], foto_resolucao)
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
        options = [("all", "Todos os estados"), ("pending", "Pendentes"), ("resolved", "Resolvidos"), ("canceled", "Cancelados")]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{value}"{sel}>{label}</option>')
        return "\n".join(parts)

    def location_options(self, locations, current):
        rows = []
        for location in locations:
            selected = "selected" if str(location["id"]) == current else ""
            label = f"Sala/WC {location['id']} - {location['name']} - {location['building']}"
            rows.append(f'<option value="{location["id"]}" {selected}>{escape(label)}</option>')
        return "\n".join(rows)

    def category_options(self, current):
        options = [("all", "Todas as categorias"), ("wc", "WC"), ("classroom", "Sala de Aula"), ("office", "Gabinete")]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{value}"{sel}>{label}</option>')
        return "\n".join(parts)

    def subcategory_options(self, categoria_local, current):
        options = [("", "Todas as localizacoes")]
        subcats = {
            "wc": ["WC do pavilhao Feminino - IP", "WC do pavilhao Masculino - IP", "WC do res-do-chao Feminino - IP", "WC do res-do-chao Masculino - IP", "WC do 1o Andar Feminino - IP", "WC do 1o Andar Masculino - IP", "WC do res-do-chao Funcionario Feminino - IP", "WC do res-do-chao Funcionario Masculino - IP", "WC do 1o Andar Funcionario Feminino - IP", "WC do 1o Andar Funcionario Masculino - IP", "WC Feminino - FD", "WC Masculino - FD", "WC Feminino - FE", "WC Masculino - FE"],
            "classroom": [f"Sala {n}" for n in range(1, 21)],
            "office": ["IP", "FE", "FD", "Reitoria"],
        }
        if categoria_local and categoria_local in subcats:
            for name in subcats[categoria_local]:
                options.append((name, name))
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{escape(value)}"{sel}>{escape(label)}</option>')
        return "\n".join(parts)

    def subcategory_options_json(self, categoria_local):
        subcats = {
            "wc": ["WC do pavilhao Feminino - IP", "WC do pavilhao Masculino - IP", "WC do res-do-chao Feminino - IP", "WC do res-do-chao Masculino - IP", "WC do 1o Andar Feminino - IP", "WC do 1o Andar Masculino - IP", "WC do res-do-chao Funcionario Feminino - IP", "WC do res-do-chao Funcionario Masculino - IP", "WC do 1o Andar Funcionario Feminino - IP", "WC do 1o Andar Funcionario Masculino - IP", "WC Feminino - FD", "WC Masculino - FD", "WC Feminino - FE", "WC Masculino - FE"],
            "classroom": [f"Sala {n}" for n in range(1, 21)],
            "office": ["IP", "FE", "FD", "Reitoria"],
        }
        return json.dumps(subcats.get(categoria_local or "wc", []))

    def period_options(self, current):
        options = [("all", "Todos os periodos"), ("morning", "Manha"), ("afternoon", "Tarde"), ("night", "Noite")]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{value}"{sel}>{label}</option>')
        return "\n".join(parts)

    def report_rows(self, reports, status, location_id, periodo, csrf_token):
        if not reports:
            return '<p class="empty">Nenhum reporte encontrado.</p>'
        rows = []
        for report in reports:
            description = f'<p class="description">{escape(report["description"])}</p>' if report["description"] else ""
            metadata = self.report_metadata(report)
            resolved_by_html = ""
            if report["status"] == "resolved":
                resolved_by_html = f'<p class="muted">Resolvido por: {escape(report.get("resolved_by_name") or "Administrador")}</p>'
            if report["status"] == "canceled":
                resolved_by_html = '<p class="muted">Marcado como falso alerta.</p>'
            report_photo = self.photo_link(report.get("foto_reporte"), "Ver foto do reporte")
            resolution_photo = self.photo_link(report.get("foto_resolucao"), "Ver foto da resolucao")
            action = ""
            if report["status"] == "pending":
                action = (
                     '<div class="report-actions">'
                     f'<form method="post" action="/admin/reports/{report["id"]}/resolve">'
                     f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                     f'<input type="hidden" name="status" value="{escape(status)}">'
                     f'<input type="hidden" name="categoria_local" value="{escape(report.get("categoria_local", "all"))}">'
                     f'<input type="hidden" name="periodo" value="{escape(periodo)}">'
                     '<button class="button button-success" type="submit">Resolver</button>'
                     "</form>"
                     f'<form method="post" action="/admin/reports/{report["id"]}/cancel">'
                     f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                     f'<input type="hidden" name="status" value="{escape(status)}">'
                     f'<input type="hidden" name="categoria_local" value="{escape(report.get("categoria_local", "all"))}">'
                     f'<input type="hidden" name="periodo" value="{escape(periodo)}">'
                     '<button class="button button-danger" type="submit">Cancelar</button>'
                     "</form></div>"
                )
            rows.append(
                '<article class="report-row"><div><div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(self.report_location_title(report))}</h2>'
                f'<p class="room-number">{escape(self.report_location_detail(report))}</p>'
                f'<p class="muted">{format_datetime(report["created_at"])}</p>'
                f"{metadata}{resolved_by_html}{description}{report_photo}{resolution_photo}</div>{action}</article>"
            )
        return "\n".join(rows)

    def cleaner_report_rows(self, reports, csrf_token):
        if not reports:
            return '<p class="empty">Nenhum reporte pendente.</p>'
        rows = []
        for report in reports:
            description = f'<p class="description">{escape(report["description"])}</p>' if report["description"] else ""
            metadata = self.report_metadata(report)
            report_photo = self.photo_link(report.get("foto_reporte"), "Ver foto do reporte")
            rows.append(
                '<article class="report-row"><div><div class="badges">'
                f'<span class="badge">#{report["id"]}</span>'
                f'<span class="badge badge-blue">{escape(ISSUE_LABELS[report["issue_type"]])}</span>'
                f'<span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span>'
                "</div>"
                f'<h2>{escape(self.report_location_title(report))}</h2>'
                f'<p class="room-number">{escape(self.report_location_detail(report))}</p>'
                f'<p class="muted">{format_datetime(report["created_at"])}</p>'
                f"{metadata}{description}{report_photo}</div>"
                f'<form class="resolve-evidence" method="post" enctype="multipart/form-data" action="/cleaner/reports/{report["id"]}/resolve">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '<input class="resolve-file" type="file" name="foto_resolucao" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required>'
                '<button class="button button-success resolve-button" type="submit" disabled>Resolver</button>'
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

                f'''<form method="post"
                    action="/admin/cleaning-users/{user["id"]}/delete"
                    onsubmit="return confirm('Tem certeza que deseja eliminar este utilizador? Esta ação não pode ser desfeita.');">'''
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '<button class="button button-danger" type="submit">Eliminar</button></form></article>'
            )
        return "\n".join(rows)

    def option_tags(self, options, current):
        rows = []
        for value, label in options:
            selected = "selected" if value == current else ""
            rows.append(f'<option value="{escape(value)}" {selected}>{escape(label)}</option>')
        return "\n".join(rows)

    def report_location_title(self, report):
        if report.get("subcategoria_local"):
            return report["subcategoria_local"]
        return report.get("location_name") or "Localizacao antiga"

    def report_location_detail(self, report):
        if report.get("categoria_local"):
            category = LOCAL_CATEGORY_LABELS.get(report["categoria_local"], report["categoria_local"])
            return f"{category} - {report.get('periodo') or 'Periodo nao indicado'}"
        if report.get("location_id"):
            return f"Numero da sala/WC: {report['location_id']} - {report.get('building') or ''}, piso {report.get('floor') or ''}"
        return "Local nao indicado"

    def report_metadata(self, report):
        parts = []
        if report.get("categoria_utilizador"):
            parts.append(f"Utilizador: {USER_CATEGORY_LABELS.get(report['categoria_utilizador'], report['categoria_utilizador'])}")
        if report.get("curso"):
            parts.append(f"Curso: {report['curso']}")
        if report.get("periodo"):
            parts.append(f"Periodo: {PERIOD_LABELS.get(report['periodo'], report['periodo'])}")
        if report.get("student_number"):
            parts.append(f"Numero de estudante: {report['student_number']}")
        return "".join(f'<p class="muted">{escape(part)}</p>' for part in parts)

    def photo_link(self, path, label):
        if not path:
            return ""
        return f'<a class="report-photo" href="{escape(path)}" target="_blank" rel="noopener">{escape(label)}</a>'

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

    def count_by_category(self, reports):
        counts = {label: 0 for label in LOCAL_CATEGORY_LABELS.values()}
        for report in reports:
            key = LOCAL_CATEGORY_LABELS.get(report.get("categoria_local"))
            if key:
                counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)

    def top_course(self, reports):
        counts = {}
        for report in reports:
            course = report.get("curso")
            if course:
                counts[course] = counts.get(course, 0) + 1
        if not counts:
            return "Sem dados"
        return max(counts.items(), key=lambda item: item[1])[0]

    def top_cleaners(self, reports, limit=5):
        counts = {}
        for report in reports:
            if report["status"] == "resolved" and report.get("resolved_by_name"):
                name = report["resolved_by_name"]
                counts[name] = counts.get(name, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
        return ranked

    def top_cleaners_html(self, reports, limit=5):
        cleaners = self.top_cleaners(reports, limit)
        if not cleaners:
            return '<p class="muted">Sem dados</p>'
        rows = []
        for i, (name, total) in enumerate(cleaners, 1):
            rows.append(
                f'<div class="top-cleaner-row">'
                f'<span class="top-cleaner-rank">{i}.</span>'
                f'<span class="top-cleaner-name">{escape(name)}</span>'
                f'<span class="top-cleaner-total">{total} resolvidos</span>'
                f'</div>'
            )
        return "\n".join(rows)

    def chart_rows(self, values):
        return [{"label": label, "value": count} for label, count in values if count > 0]

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

    def uploaded_file(self, request_path):
        filename = Path(request_path).name
        path = (UPLOAD_DIR / filename).resolve()
        upload_root = UPLOAD_DIR.resolve()
        if upload_root not in path.parents or not path.exists():
            return self.not_found()
        extension = path.suffix.lower()
        content_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
        }
        return self.static_file(path, content_types.get(extension, "application/octet-stream"))

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
