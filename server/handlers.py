import json
import re
import secrets
from datetime import datetime
from email.parser import BytesParser
from email.policy import default as email_policy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

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
    duration_seconds,
    escape,
    format_datetime,
    format_duration,
    get_period,
    is_valid_email,
    is_valid_password,
    is_valid_username,
    redirect_target,
    render_template,
    waiting_level,
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
            return self.redirect("/admin/dashboard")
        if parsed.path == "/admin/dashboard":
            return self.show_admin_dashboard(parse_qs(parsed.query))
        if parsed.path == "/admin/reports":
            return self.show_admin_reports(parse_qs(parsed.query))
        if parsed.path == "/admin/users":
            return self.show_admin_users(parse_qs(parsed.query))
        if parsed.path == "/admin/monthly-report":
            return self.show_monthly_report(parse_qs(parsed.query))
        if parsed.path == "/admin/monthly-report.pdf":
            return self.monthly_report_pdf(parse_qs(parsed.query))
        if parsed.path == "/admin/reports/print":
            return self.print_filtered_reports(parse_qs(parsed.query), auto_print=True)
        if parsed.path == "/admin/reports/export-pdf":
            return self.print_filtered_reports(parse_qs(parsed.query), auto_print=True)
        if parsed.path == "/admin/reports/export-excel":
            return self.export_filtered_reports_excel(parse_qs(parsed.query))
        if parsed.path == "/cleaner":
            return self.show_cleaner(parse_qs(parsed.query))
        if parsed.path == "/api/admin/notification-email":
            return self.get_notification_email_api()
        if parsed.path == "/static/styles.css":
            return self.static_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
        if parsed.path == "/static/js/chart.umd.min.js":
            return self.static_file(STATIC_DIR / "js" / "chart.umd.min.js", "application/javascript; charset=utf-8")
        if parsed.path.startswith("/static/uploads/"):
            return self.uploaded_file(parsed.path)
        match = re.fullmatch(r"/admin/reports/(\d+)/print", parsed.path)
        if match:
            return self.print_report(int(match.group(1)))
        match = re.fullmatch(r"/view-photo", parsed.path)
        if match:
            return self.view_photo(parse_qs(parsed.query))
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
        match = re.fullmatch(r"/admin/reports/(\d+)/start", parsed.path)
        if match:
            return self.start_report(int(match.group(1)))
        match = re.fullmatch(r"/admin/reports/(\d+)/cancel", parsed.path)
        if match:
            return self.cancel_report(int(match.group(1)))
        match = re.fullmatch(r"/admin/cleaning-users/(\d+)/delete", parsed.path)
        if match:
            return self.delete_cleaning_user_form(int(match.group(1)))
        match = re.fullmatch(r"/admin/cleaning-users/(\d+)/update", parsed.path)
        if match:
            return self.update_cleaning_user_form(int(match.group(1)))
        match = re.fullmatch(r"/cleaner/reports/(\d+)/resolve", parsed.path)
        if match:
            return self.resolve_report_cleaner(int(match.group(1)))
        match = re.fullmatch(r"/cleaner/reports/(\d+)/start", parsed.path)
        if match:
            return self.start_report_cleaner(int(match.group(1)))
        match = re.fullmatch(r"/cleaner/reports/(\d+)/false-alert", parsed.path)
        if match:
            return self.mark_false_alert_cleaner(int(match.group(1)))
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
        header_type = f"Content-Type: {content_type}\r\n"
        header_length = f"Content-Length: {length}\r\n"
        raw_message = (
            header_type + header_length +
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
        issue_emojis = {
            "paper": "🧻",
            "soap": "🧼",
            "dirty": "🚽",
            "smell": "👃",
            "water": "💧",
            "other": "❓",
        }
        for issue_id, label in ISSUE_LABELS.items():
            checked = "checked" if selected_issue == issue_id else ""
            emoji = issue_emojis.get(issue_id, "")
            issue_buttons.append(
                '<label class="problem-card">'
                f'<input type="radio" name="issue_type" value="{issue_id}" {checked} required>'
                f"<span>{escape(emoji)} {escape(label)}</span>"
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
            if str(exc) == "missing":
                return self.show_report(query, "E obrigatorio anexar uma fotografia para submeter um relatorio.")
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

    def admin_filters_from_query(self, query):
        status = clean_text((query.get("status") or ["all"])[0], 20)
        location_id = clean_text((query.get("location_id") or ["all"])[0], 20)
        categoria_local = clean_text((query.get("categoria_local") or ["all"])[0], 20)
        subcategoria_local = clean_text((query.get("subcategoria_local") or [""])[0], 160)
        issue_type = clean_text((query.get("issue_type") or ["all"])[0], 20)
        curso = clean_text((query.get("curso") or ["all"])[0], 120)
        date_from = clean_text((query.get("date_from") or [""])[0], 20)
        date_to = clean_text((query.get("date_to") or [""])[0], 20)
        month = clean_text((query.get("month") or [datetime.now().strftime("%Y-%m")])[0], 7)
        if date_from and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from):
            date_from = ""
        if date_to and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to):
            date_to = ""
        if month and not re.fullmatch(r"\d{4}-\d{2}", month):
            month = datetime.now().strftime("%Y-%m")
        periodo = clean_text((query.get("periodo") or ["all"])[0], 20)
        return {
            "status": status,
            "location_id": location_id,
            "categoria_local": categoria_local,
            "subcategoria_local": subcategoria_local,
            "issue_type": issue_type,
            "curso": curso,
            "date_from": date_from,
            "date_to": date_to,
            "month": month,
            "periodo": periodo,
        }

    def reports_for_filters(self, filters):
        return database.filtered_reports(
            filters["status"],
            filters["location_id"],
            categoria_local=filters["categoria_local"] if filters["categoria_local"] != "all" else None,
            subcategoria_local=filters["subcategoria_local"] or None,
            periodo=filters["periodo"] if filters["periodo"] != "all" else None,
            issue_type=filters["issue_type"] if filters["issue_type"] != "all" else None,
            curso=filters["curso"] if filters["curso"] != "all" else None,
            date_from=filters["date_from"] or None,
            date_to=filters["date_to"] or None,
        )

    def show_admin(self, query):
        if not auth.valid_admin_cookie(self.headers):
            csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
            body = render_template("admin_login.html", error_html="", csrf_token=escape(csrf_token))
            return self.html_response(body, csrf_token=csrf_token if is_new else None)

        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        filters = self.admin_filters_from_query(query)
        reports = self.reports_for_filters(filters)
        monthly_reports = database.monthly_reports(filters["month"]) if re.fullmatch(r"\d{4}-\d{2}", filters["month"]) else []
        stats = self.dashboard_stats(reports)
        monthly_stats = self.monthly_stats(monthly_reports)
        cleaning_users = database.list_cleaning_users()
        for user in cleaning_users:
            user["false_alert_count"] = database.count_false_alerts_by_cleaner(user["id"])
        false_alert_count = sum(1 for report in reports if report.get("falso_alerta"))
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            settings_message=self.settings_message((query.get("settings") or [""])[0]),
            users_message=self.users_message((query.get("users") or [""])[0]),
            cleaning_user_rows=self.cleaning_user_rows(cleaning_users=cleaning_users, csrf_token=csrf_token),
            cleaning_users_total=len(cleaning_users),
            cleaning_users_notify_count=sum(1 for user in cleaning_users if user.get("receives_notifications")),
            cleaning_users_no_notify_count=sum(1 for user in cleaning_users if not user.get("receives_notifications")),
            total_count=len(reports),
            pending_count=stats["pending_count"],
            in_progress_count=stats["in_progress_count"],
            resolved_count=stats["resolved_count"],
            canceled_count=stats["canceled_count"],
            resolution_rate=stats["resolution_rate"],
            false_alert_count=false_alert_count,
            admin_tab="dashboard",
            top_course=escape(self.top_course(reports)),
            cleaning_users_json=json.dumps([{
                "id": u["id"],
                "name": u["name"],
                "username": u["username"],
                "email": u["email"] or "",
                "receives_notifications": u["receives_notifications"],
                "active": u["active"],
                "false_alert_count": u.get("false_alert_count", 0)
            } for u in cleaning_users]),
            status_options=self.status_options(filters["status"]),
            category_options=self.category_options(filters["categoria_local"]),
            issue_filter_options=self.issue_filter_options(filters["issue_type"]),
            course_filter_options=self.course_filter_options(filters["curso"]),
            periodo_options=self.period_options(filters["periodo"]),
            subcategory_options=self.subcategory_options(filters["categoria_local"], filters["subcategoria_local"]),
            subcategory_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            report_rows=self.report_rows(
                reports,
                {
                    "status": filters["status"],
                    "categoria_local": filters["categoria_local"],
                    "subcategoria_local": filters["subcategoria_local"],
                    "periodo": filters["periodo"],
                    "issue_type": filters["issue_type"],
                    "curso": filters["curso"],
                    "date_from": filters["date_from"],
                    "date_to": filters["date_to"],
                },
                csrf_token,
            ),
            current_query=escape(urlencode({key: value for key, value in filters.items() if value and key != "month"})),
            monthly_total=monthly_stats["total"],
            monthly_resolved=monthly_stats["resolved"],
            monthly_pending=monthly_stats["pending"],
            monthly_resolution_rate=escape(monthly_stats["resolution_rate"]),
            month_query=escape(filters["month"]),
            date_from_query=escape(filters["date_from"]),
            date_to_query=escape(filters["date_to"]),
            subcategoria_query=escape(filters["subcategoria_local"]),
            top_cleaners_html=self.top_cleaners_html(reports),
            chart_payload=json.dumps(
                {
                    "byDay": self.chart_rows(self.count_by_day(reports)),
                    "byMonth": self.chart_rows(self.count_by_month(reports)),
                    "byIssue": self.chart_rows(self.count_by_issue(reports)),
                    "byCategory": self.chart_rows(self.count_by_category(reports)),
                    "byStatus": self.chart_rows(self.count_by_status(reports)),
                    "byPeriod": self.chart_rows(self.count_by_period(reports)),
                    "byCourse": self.chart_rows(self.count_by_course(reports)),
                }
            ),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def show_admin_dashboard(self, query):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        filters = self.admin_filters_from_query(query)
        reports = self.reports_for_filters(filters)
        monthly_reports = database.monthly_reports(filters["month"]) if re.fullmatch(r"\d{4}-\d{2}", filters["month"]) else []
        stats = self.dashboard_stats(reports)
        monthly_stats = self.monthly_stats(monthly_reports)
        false_alert_count = sum(1 for report in reports if report.get("falso_alerta"))
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            settings_message=self.settings_message((query.get("settings") or [""])[0]),
            users_message="",
            cleaning_user_rows="",
            cleaning_users_total=0,
            cleaning_users_notify_count=0,
            cleaning_users_no_notify_count=0,
            total_count=len(reports),
            pending_count=stats["pending_count"],
            in_progress_count=stats["in_progress_count"],
            resolved_count=stats["resolved_count"],
            canceled_count=stats["canceled_count"],
            resolution_rate=stats["resolution_rate"],
            false_alert_count=false_alert_count,
            top_course=escape(self.top_course(reports)),
            cleaning_users_json="[]",
            status_options=self.status_options(filters["status"]),
            category_options=self.category_options(filters["categoria_local"]),
            issue_filter_options=self.issue_filter_options(filters["issue_type"]),
            course_filter_options=self.course_filter_options(filters["curso"]),
            periodo_options=self.period_options(filters["periodo"]),
            subcategory_options=self.subcategory_options(filters["categoria_local"], filters["subcategoria_local"]),
            subcategory_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            report_rows="",
            current_query=escape(urlencode({key: value for key, value in filters.items() if value and key != "month"})),
            monthly_total=monthly_stats["total"],
            monthly_resolved=monthly_stats["resolved"],
            monthly_pending=monthly_stats["pending"],
            monthly_resolution_rate=escape(monthly_stats["resolution_rate"]),
            month_query=escape(filters["month"]),
            date_from_query=escape(filters["date_from"]),
            date_to_query=escape(filters["date_to"]),
            subcategoria_query=escape(filters["subcategoria_local"]),
            top_cleaners_html=self.top_cleaners_html(reports),
            chart_payload=json.dumps(
                {
                    "byDay": self.chart_rows(self.count_by_day(reports)),
                    "byMonth": self.chart_rows(self.count_by_month(reports)),
                    "byIssue": self.chart_rows(self.count_by_issue(reports)),
                    "byCategory": self.chart_rows(self.count_by_category(reports)),
                    "byStatus": self.chart_rows(self.count_by_status(reports)),
                    "byPeriod": self.chart_rows(self.count_by_period(reports)),
                    "byCourse": self.chart_rows(self.count_by_course(reports)),
                }
            ),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def show_admin_reports(self, query):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        filters = self.admin_filters_from_query(query)
        reports = self.reports_for_filters(filters)
        monthly_reports = database.monthly_reports(filters["month"]) if re.fullmatch(r"\d{4}-\d{2}", filters["month"]) else []
        monthly_stats = self.monthly_stats(monthly_reports)
        stats = self.dashboard_stats(reports)
        false_alert_count = sum(1 for report in reports if report.get("falso_alerta"))
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            settings_message=self.settings_message((query.get("settings") or [""])[0]),
            users_message="",
            cleaning_user_rows="",
            cleaning_users_total=0,
            cleaning_users_notify_count=0,
            cleaning_users_no_notify_count=0,
            total_count=len(reports),
            pending_count=stats["pending_count"],
            in_progress_count=stats["in_progress_count"],
            resolved_count=stats["resolved_count"],
            canceled_count=stats["canceled_count"],
            resolution_rate=stats["resolution_rate"],
            false_alert_count=false_alert_count,
            top_course="",
            admin_tab="reports",
            cleaning_users_json="[]",
            status_options=self.status_options(filters["status"]),
            category_options=self.category_options(filters["categoria_local"]),
            issue_filter_options=self.issue_filter_options(filters["issue_type"]),
            course_filter_options=self.course_filter_options(filters["curso"]),
            periodo_options=self.period_options(filters["periodo"]),
            subcategory_options=self.subcategory_options(filters["categoria_local"], filters["subcategoria_local"]),
            subcategory_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            report_rows=self.report_rows(
                reports,
                {
                    "status": filters["status"],
                    "categoria_local": filters["categoria_local"],
                    "subcategoria_local": filters["subcategoria_local"],
                    "periodo": filters["periodo"],
                    "issue_type": filters["issue_type"],
                    "curso": filters["curso"],
                    "date_from": filters["date_from"],
                    "date_to": filters["date_to"],
                },
                csrf_token,
            ),
            current_query=escape(urlencode({key: value for key, value in filters.items() if value and key != "month"})),
            monthly_total=monthly_stats["total"],
            monthly_resolved=monthly_stats["resolved"],
            monthly_pending=monthly_stats["pending"],
            monthly_resolution_rate=escape(monthly_stats["resolution_rate"]),
            month_query=escape(filters["month"]),
            date_from_query=escape(filters["date_from"]),
            date_to_query=escape(filters["date_to"]),
            subcategoria_query=escape(filters["subcategoria_local"]),
            top_cleaners_html="",
            chart_payload=json.dumps({}),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def show_admin_users(self, query):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        cleaning_users = database.list_cleaning_users()
        for user in cleaning_users:
            user["false_alert_count"] = database.count_false_alerts_by_cleaner(user["id"])
        body = render_template(
            "admin.html",
            csrf_token=escape(csrf_token),
            settings_message="",
            users_message=self.users_message((query.get("users") or [""])[0]),
            cleaning_user_rows=self.cleaning_user_rows(cleaning_users=cleaning_users, csrf_token=csrf_token),
            cleaning_users_total=len(cleaning_users),
            cleaning_users_notify_count=sum(1 for user in cleaning_users if user.get("receives_notifications")),
            cleaning_users_no_notify_count=sum(1 for user in cleaning_users if not user.get("receives_notifications")),
            total_count=0,
            pending_count=0,
            in_progress_count=0,
            resolved_count=0,
            canceled_count=0,
            resolution_rate="0%",
            false_alert_count=0,
            top_course="",
            admin_tab="users",
            cleaning_users_json=json.dumps([{
                "id": u["id"],
                "name": u["name"],
                "username": u["username"],
                "email": u["email"] or "",
                "receives_notifications": u["receives_notifications"],
                "active": u["active"],
                "false_alert_count": u.get("false_alert_count", 0)
            } for u in cleaning_users]),
            status_options="",
            category_options="",
            issue_filter_options="",
            course_filter_options="",
            periodo_options="",
            subcategory_options="",
            subcategory_options_json=json.dumps(LOCAL_SUBCATEGORY_OPTIONS),
            report_rows="",
            current_query="",
            monthly_total=0,
            monthly_resolved=0,
            monthly_pending=0,
            monthly_resolution_rate="0%",
            month_query="",
            date_from_query="",
            date_to_query="",
            subcategoria_query="",
            top_cleaners_html="",
            chart_payload=json.dumps({}),
        )
        return self.html_response(body, csrf_token=csrf_token if is_new else None)

    def show_cleaner(self, query):
        cleaner = database.get_cleaner_by_session(auth.get_cleaner_session_token(self.headers))
        if not cleaner:
            error_status = (query.get("error") or [""])[0]
            body = render_template(
                "cleaner_login.html",
                csrf_token=escape(csrf_token) if 'csrf_token' in dir() else "",
                error_html=self.cleaner_login_error(error_status),
            )
            return self.html_response(body)
        csrf_token, is_new = auth.get_or_create_csrf_token(self.headers)
        in_progress_count = sum(1 for report in reports if report["status"] == "in_progress")
        resolved_count = sum(1 for report in reports if report["status"] == "resolved")
        false_alert_count = sum(1 for report in reports if report.get("falso_alerta"))
        total_count = pending_count + in_progress_count + resolved_count + false_alert_count
        logger.info(
            "cleaner_kpis user=%s pending=%d in_progress=%d resolved=%d false_alerts=%d total=%d",
            cleaner["username"],
            pending_count,
            in_progress_count,
            resolved_count,
            false_alert_count,
            total_count,
        )
        body = render_template(
            "cleaner_dashboard.html",
            csrf_token=escape(csrf_token),
            cleaner_name=escape(cleaner["name"]),
            cleaner_username=escape(cleaner["username"]),
            cleaner_email=escape(cleaner["email"] or "Sem email associado"),
            report_rows=self.cleaner_report_rows(reports, csrf_token),
            total_count=total_count,
            pending_count=pending_count,
            in_progress_count=in_progress_count,
            resolved_count=resolved_count,
            false_alert_count=false_alert_count,
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
            return self.redirect("/admin/users")
        form = self.safe_form_or_redirect("/admin/users")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin/users?users=csrf")

        name = clean_text(form.get("name", ""), 120)
        username = clean_text(form.get("username", ""), 40).lower()
        email = clean_text(form.get("email", ""), 180)
        password = form.get("password", "")

        if not name or not is_valid_username(username) or not is_valid_password(password) or (email and not is_valid_email(email)):
            return self.redirect("/admin/users?users=invalid")
        try:
            database.create_cleaning_user(name, username, email, password)
        except psycopg2.IntegrityError:
            return self.redirect("/admin/users?users=duplicate")
        logger.info("cleaning_user_created username=%s", username)
        return self.redirect("/admin/users?users=created")

    def update_cleaning_user_form(self, user_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin/users")
        form = self.safe_form_or_redirect("/admin/users")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin/users?users=csrf")

        name = clean_text(form.get("name", ""), 120)
        username = clean_text(form.get("username", ""), 40).lower()
        email = clean_text(form.get("email", ""), 180)
        password = form.get("password", "")
        receives_notifications = form.get("receives_notifications") == "on"

        if not name or not is_valid_username(username) or (password and not is_valid_password(password)) or (email and not is_valid_email(email)):
            return self.redirect("/admin/users?users=invalid")
        try:
            database.update_cleaning_user(user_id, name, username, email, receives_notifications, password)
        except psycopg2.IntegrityError:
            return self.redirect("/admin/users?users=duplicate")
        return self.redirect("/admin/users?users=updated")

    def delete_cleaning_user_form(self, user_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin/users")
        form = self.safe_form_or_redirect("/admin/users")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin/users?users=csrf")
        database.delete_cleaning_user(user_id)
        return self.redirect("/admin/users?users=deleted")

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

    def admin_redirect_filters(self, form):
        return {
            "status": form.get("status", "pending"),
            "categoria_local": form.get("categoria_local", "all"),
            "subcategoria_local": form.get("subcategoria_local", ""),
            "periodo": form.get("periodo", "all"),
            "issue_type": form.get("issue_type", "all"),
            "curso": form.get("curso", "all"),
            "date_from": form.get("date_from", ""),
            "date_to": form.get("date_to", ""),
        }

    def start_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        database.start_report(report_id)
        return self.redirect(redirect_target("/admin", self.admin_redirect_filters(form)))

    def resolve_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        database.resolve_report(report_id)
        return self.redirect(redirect_target("/admin", self.admin_redirect_filters(form)))

    def cancel_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        form = self.safe_form_or_redirect("/admin")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/admin")
        database.cancel_report(report_id)
        return self.redirect(redirect_target("/admin", self.admin_redirect_filters(form)))

    def start_report_cleaner(self, report_id):
        cleaner = database.get_cleaner_by_session(auth.get_cleaner_session_token(self.headers))
        if not cleaner:
            return self.redirect("/cleaner")
        form = self.safe_form_or_redirect("/cleaner")
        if form is None:
            return
        if not auth.valid_csrf(self.headers, form):
            return self.redirect("/cleaner")
        database.start_report(report_id, cleaner["id"])
        return self.redirect("/cleaner")

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

    def mark_false_alert_cleaner(self, report_id):
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
        database.mark_false_alert(report_id, cleaner["id"], foto_resolucao)
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
        options = [("all", "Todos os estados"), ("pending", "Pendentes"), ("in_progress", "Em resolucao"), ("resolved", "Resolvidos"), ("canceled", "Cancelados")]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{value}"{sel}>{label}</option>')
        return "\n".join(parts)

    def issue_filter_options(self, current):
        options = [("all", "Todos os tipos"), *ISSUE_LABELS.items()]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{escape(value)}"{sel}>{escape(label)}</option>')
        return "\n".join(parts)

    def course_filter_options(self, current):
        options = [("all", "Todos os cursos"), *((value, value) for value in COURSE_OPTIONS)]
        parts = []
        for value, label in options:
            sel = ' selected' if value == current else ''
            parts.append(f'<option value="{escape(value)}"{sel}>{escape(label)}</option>')
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

    def hidden_filter_inputs(self, filters):
        return "".join(
            f'<input type="hidden" name="{escape(key)}" value="{escape(value)}">'
            for key, value in filters.items()
        )

    def report_timing_html(self, report):
        wait_seconds = duration_seconds(report.get("created_at"), report.get("started_at"))
        resolution_seconds = duration_seconds(report.get("started_at"), report.get("resolved_at"))
        parts = [
            f"Tempo de espera: {format_duration(wait_seconds)}",
            f"Tempo de resolucao: {format_duration(resolution_seconds)}",
        ]
        if report.get("started_at"):
            parts.append(f"Inicio: {format_datetime(report['started_at'])}")
        if report.get("resolved_at"):
            parts.append(f"Conclusao: {format_datetime(report['resolved_at'])}")
        return "".join(f'<p class="muted">{escape(part)}</p>' for part in parts)

    def wait_duration_label(self, report):
        return format_duration(duration_seconds(report.get("created_at"), report.get("started_at")))

    def resolution_duration_label(self, report):
        return format_duration(duration_seconds(report.get("started_at"), report.get("resolved_at")))

    def report_actions_html(self, report, filters, csrf_token):
        hidden = self.hidden_filter_inputs(filters)
        actions = []
        status_block = ""
        if report["status"] == "pending":
            status_block = (
                f'<form method="post" action="/admin/reports/{report["id"]}/start">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">{hidden}'
                '<button class="button button-warning action-status-button" type="submit" title="Em Resolucao">Em Resolucao</button></form>'
            )
        elif report["status"] == "in_progress":
            status_block = '<span class="badge badge-warning action-status-label">Em Resolucao</span>'

        if report["status"] in {"pending", "in_progress"}:
            actions.append(
                f'<form method="post" action="/admin/reports/{report["id"]}/resolve">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">{hidden}'
                '<button class="icon-action-button button-success" type="submit" title="Resolver">✔</button></form>'
            )
            actions.append(
                f'<form method="post" action="/admin/reports/{report["id"]}/cancel">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">{hidden}'
                '<button class="icon-action-button button-danger" type="submit" title="Falso Alerta">✕</button></form>'
            )

        if not status_block and not actions:
            return '<div class="actions-cell"></div>'

        buttons_html = "".join(actions)
        return (
            '<div class="actions-cell">'
            f'{status_block}'
            f'<div class="actions-buttons">{buttons_html}</div>'
            '</div>'
        )

    def cleaner_report_rows(self, reports, csrf_token):
        if not reports:
            return '<tr><td colspan="11" class="empty">Nenhuma ocorrencia encontrada.</td></tr>'
        rows = []
        for report in reports:
            status_label = STATUS_LABELS.get(report["status"], report["status"])
            status_class = "badge-status"
            row_class = f'report-wait-{waiting_level(report.get("created_at"), report.get("status"))}'
            if report.get("falso_alerta"):
                status_label = "Falso Alerta"
                status_class = "badge-danger"
                row_class = "report-wait-done cleaner-false-alert"
            elif report["status"] == "resolved":
                status_class = "badge-green"
                row_class = "cleaner-resolved"
            elif report["status"] == "in_progress":
                status_class = "badge-warning"
                row_class = "report-wait-warning"
            elif report["status"] == "pending" and waiting_level(report.get("created_at"), report.get("status")) == "late":
                row_class = "report-wait-late"

            photo_count = sum(1 for path in [report.get("foto_reporte"), report.get("foto_resolucao")] if path)
            photo_label = "Sem Fotos" if photo_count == 0 else f"{photo_count} Foto" + ("s" if photo_count > 1 else "")
            photo_button = (
                '<button class="button button-secondary photos-button" type="button"'
                f' data-occurrence-photo="{escape(report.get("foto_reporte") or "")}"'
                f' data-resolution-photo="{escape(report.get("foto_resolucao") or "")}"'
                f' title="{escape(photo_label)}">'
                f'📷 {escape(photo_label)}</button>'
            )
            start_action = ""
            if report["status"] == "pending":
                start_action = (
                    f'<form method="post" action="/cleaner/reports/{report["id"]}/start">'
                    f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                    '<button class="button button-warning" type="submit">Em Resolucao</button>'
                    '</form>'
                )
            resolve_actions = ""
            if report["status"] in {"pending", "in_progress"}:
                resolve_actions = (
                    f'<form class="resolve-evidence" method="post" enctype="multipart/form-data" action="/cleaner/reports/{report["id"]}/resolve">'
                    f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                    '<input class="resolve-file" type="file" name="foto_resolucao" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required>'
                    '<button class="button button-success resolve-button" type="submit" disabled>Resolver</button>'
                    f'</form>'
                    f'<form class="resolve-evidence" method="post" enctype="multipart/form-data" action="/cleaner/reports/{report["id"]}/false-alert">'
                    f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                    '<input class="resolve-file" type="file" name="foto_resolucao" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required>'
                    '<button class="button button-danger resolve-button" type="submit" disabled>Falso Alerta</button>'
                    '</form>'
                )
            search_text = " ".join(
                str(value or "")
                for value in [
                    report["id"],
                    self.report_location_title(report),
                    ISSUE_LABELS.get(report["issue_type"]),
                    status_label,
                ]
            )
            rows.append(
                f'<tr class="{escape(row_class)}" data-status="{escape(report["status"])}" data-false-alert="{"yes" if report.get("falso_alerta") else "no"}" data-search="{escape(search_text).lower()}">'
                f'<td data-sort="{report["id"]}">#{report["id"]}</td>'
                f'<td data-sort="{format_datetime(report["created_at"])}">{format_datetime(report["created_at"])}</td>'
                f'<td>{escape(self.report_location_title(report))}</td>'
                f'<td>{escape(ISSUE_LABELS[report["issue_type"]])}</td>'
                f'<td>{escape(PERIOD_LABELS.get(report.get("periodo"), report.get("periodo") or ""))}</td>'
                f'<td><span class="badge {status_class}">{escape(status_label)}</span></td>'
                f'<td>{escape(self.wait_duration_label(report))}</td>'
                f'<td>{escape(self.resolution_duration_label(report))}</td>'
                f'<td>{escape(report.get("description") or "")}</td>'
                f'<td class="photos-cell">{photo_button}</td>'
                f'<td><div class="table-actions cleaner-actions">{start_action}{resolve_actions}</div></td>'
                "</tr>"
            )
        return "\n".join(rows)

    def report_rows(self, reports, filters, csrf_token):
        if not reports:
            return '<tr><td colspan="11" class="empty">Nenhum reporte encontrado.</td></tr>'
        rows = []
        for report in reports:
            responsible = report.get("resolved_by_name") or report.get("started_by_name") or ""
            level = waiting_level(report.get("created_at"), report.get("status"))
            search_text = " ".join(
                str(value or "")
                for value in [
                    report["id"],
                    format_datetime(report["created_at"]),
                    self.report_location_title(report),
                    ISSUE_LABELS.get(report["issue_type"]),
                    PERIOD_LABELS.get(report.get("periodo")),
                    STATUS_LABELS.get(report["status"]),
                    responsible,
                    report.get("curso") or "",
                ]
            )
            photo_count = sum(1 for path in [report.get("foto_reporte"), report.get("foto_resolucao")] if path)
            photo_label = "Sem Fotos" if photo_count == 0 else f"{photo_count} Foto" + ("s" if photo_count > 1 else "")
            photo_button = (
                '<button class="button button-secondary photos-button admin-photos-button" type="button"'
                f' data-report-id="#{report["id"]}"'
                f' data-report-date="{escape(format_datetime(report["created_at"]))}"'
                f' data-report-location="{escape(self.report_location_title(report))}"'
                f' data-report-category="{escape(ISSUE_LABELS[report["issue_type"]])}"'
                f' data-report-status="{escape(STATUS_LABELS[report["status"]])}"'
                f' data-report-responsible="{escape(responsible)}"'
                f' data-occurrence-photo="{escape(report.get("foto_reporte") or "")}"'
                f' data-resolution-photo="{escape(report.get("foto_resolucao") or "")}"'
                f' title="{escape(photo_label)}">'
                f'📷 {escape(photo_label)}</button>'
            )
            rows.append(
                f'<tr class="report-wait-{escape(level)}" data-search="{escape(search_text).lower()}">'
                f'<td data-sort="{report["id"]}">#{report["id"]}</td>'
                f'<td data-sort="{format_datetime(report["created_at"])}">{format_datetime(report["created_at"])}</td>'
                f'<td>{escape(self.report_location_title(report))}</td>'
                f'<td>{escape(ISSUE_LABELS[report["issue_type"]])}</td>'
                f'<td>{escape(PERIOD_LABELS.get(report.get("periodo"), report.get("periodo") or ""))}</td>'
                f'<td><span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span></td>'
                f'<td>{escape(self.wait_duration_label(report))}</td>'
                f'<td>{escape(self.resolution_duration_label(report))}</td>'
                f'<td>{escape(responsible)}</td>'
                f'<td class="photos-cell">{photo_button}</td>'
                f'<td>{self.report_actions_html(report, filters, csrf_token)}</td>'
                "</tr>"
            )
        return "\n".join(rows)

    def cleaning_user_rows(self, cleaning_users, csrf_token):
        if not cleaning_users:
            return '<tr><td colspan="6" class="empty">Nenhum utilizador de limpeza criado.</td></tr>'

        rows = []

        for user in cleaning_users:
            checked = "checked" if user["receives_notifications"] else ""
            notify_state = "yes" if user["receives_notifications"] else "no"
            search_text = f'{user["name"]} {user["username"]} {user["email"] or ""}'

            rows.append(
                f'<tr data-search="{escape(search_text).lower()}" data-notify="{notify_state}">'
                f'<td><input form="user-save-{user["id"]}" class="row-input" type="text" name="name" value="{escape(user["name"])}" readonly disabled></td>'
                f'<td><input form="user-save-{user["id"]}" class="row-input" type="text" name="username" value="{escape(user["username"])}" readonly disabled></td>'
                f'<td><input form="user-save-{user["id"]}" class="row-input" type="email" name="email" value="{escape(user["email"] or "")}" placeholder="email@exemplo.com" readonly disabled></td>'
                '<td class="password-cell">'
                '<span class="password-mask">********</span>'
                '<div class="password-edit-group">'
                f'<input form="user-save-{user["id"]}" class="row-input password-input" type="password" name="password" placeholder="********" disabled>'
                '<button class="action-btn password-toggle-button" type="button" title="Mostrar/Ocultar senha">👁</button>'
                '</div></td>'
                '<td class="notifications-cell">'
                f'<label class="check-field"><input form="user-save-{user["id"]}" class="notify-checkbox" type="checkbox" name="receives_notifications" {checked} disabled aria-label="Recebe notificacoes"></label>'
                '</td>'
                '<td class="actions-cell">'
                '<div class="action-btn-group">'
                '<button class="action-btn action-edit-button" type="button" title="Editar">✏️</button>'
                f'<button class="action-btn action-save-button" type="submit" form="user-save-{user["id"]}" title="Guardar" hidden>💾</button>'
                '<button class="action-btn action-cancel-button" type="button" title="Cancelar" hidden>↩️</button>'
                f'<form class="delete-form" method="post" action="/admin/cleaning-users/{user["id"]}/delete" onsubmit="return confirm(\'Tem certeza que deseja eliminar este utilizador? Esta acao nao pode ser desfeita.\');">'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '<button class="action-btn action-delete-button" type="submit" title="Eliminar">🗑️</button>'
                '</form>'
                '</div>'
                f'<form id="user-save-{user["id"]}" method="post" action="/admin/cleaning-users/{user["id"]}/update" hidden>'
                f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
                '</form>'
                '</td></tr>'
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

    def photo_link(self, path, label, photo_type=None, report_id=None):
        if not path or not report_id:
            return ""
        return f'<a class="report-photo" href="/view-photo?id={report_id}&type={photo_type}" target="_blank" rel="noopener">{escape(label)}</a>'

    def count_by_day(self, reports):
        counts = {}
        for report in reports:
            key = day_key(report["created_at"])
            counts[key] = counts.get(key, 0) + 1
        return list(counts.items())[:7]

    def count_by_month(self, reports):
        counts = {}
        for report in reports:
            key = str(report["created_at"])[:7]
            counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items())[-12:]

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

    def count_by_status(self, reports):
        counts = {label: 0 for label in STATUS_LABELS.values()}
        for report in reports:
            key = STATUS_LABELS.get(report.get("status"))
            if key:
                counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)

    def count_by_location(self, reports):
        counts = {}
        for report in reports:
            key = self.report_location_title(report)
            counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:12]

    def count_by_period(self, reports):
        counts = {"Manha": 0, "Tarde": 0, "Noite": 0}
        for report in reports:
            period = get_period(report.get("created_at"))
            label = PERIOD_LABELS.get(period, "Manha")
            counts[label] = counts.get(label, 0) + 1
        return list(counts.items())

    def count_by_course(self, reports):
        counts = {}
        for report in reports:
            course = report.get("curso")
            if not course:
                continue
            counts[course] = counts.get(course, 0) + 1
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

    def average_duration(self, reports, start_key, end_key):
        values = [
            duration_seconds(report.get(start_key), report.get(end_key))
            for report in reports
            if report.get(start_key) and report.get(end_key)
        ]
        values = [value for value in values if value is not None]
        if not values:
            return "Ainda sem dados"
        return format_duration(sum(values) / len(values))

    def dashboard_stats(self, reports):
        total = len(reports)
        resolved = sum(1 for report in reports if report["status"] == "resolved")
        return {
            "pending_count": sum(1 for report in reports if report["status"] == "pending"),
            "in_progress_count": sum(1 for report in reports if report["status"] == "in_progress"),
            "resolved_count": resolved,
            "canceled_count": sum(1 for report in reports if report["status"] == "canceled"),
            "avg_wait_time": self.average_duration(reports, "created_at", "started_at"),
            "avg_resolution_time": self.average_duration(reports, "started_at", "resolved_at"),
            "resolution_rate": f"{round((resolved / total) * 100)}%" if total else "0%",
        }

    def monthly_stats(self, reports):
        total = len(reports)
        resolved = sum(1 for report in reports if report["status"] == "resolved")
        pending = sum(1 for report in reports if report["status"] == "pending")
        return {
            "total": total,
            "resolved": resolved,
            "pending": pending,
            "resolution_rate": self.resolution_rate(reports),
            "avg_wait": self.average_duration(reports, "created_at", "started_at"),
            "avg_resolution": self.average_duration(reports, "started_at", "resolved_at"),
            "by_issue": self.count_by_issue(reports),
            "by_period": self.count_by_period(reports),
        }

    def resolution_rate(self, reports):
        total = len(reports)
        if not total:
            return "0%"
        resolved = sum(1 for report in reports if report["status"] == "resolved")
        return f"{round((resolved / total) * 100)}%"

    def printable_report_html(self, report):
        return (
            '<!doctype html><html lang="pt-PT"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Imprimir reporte</title><link rel="stylesheet" href="/static/styles.css"></head>'
            '<body class="print-body"><main class="print-page">'
            f'<h1>Reporte #{report["id"]}</h1>'
            f'<p><strong>Estado:</strong> {escape(STATUS_LABELS[report["status"]])}</p>'
            f'<p><strong>Tipo:</strong> {escape(ISSUE_LABELS[report["issue_type"]])}</p>'
            f'<p><strong>Local:</strong> {escape(self.report_location_title(report))}</p>'
            f'<p><strong>Detalhe:</strong> {escape(self.report_location_detail(report))}</p>'
            f'<p><strong>Criado em:</strong> {format_datetime(report["created_at"])}</p>'
            f'{self.report_timing_html(report)}'
            f'<p><strong>Descricao:</strong> {escape(report.get("description") or "Sem descricao")}</p>'
            '<button class="button button-secondary print-button" onclick="window.print()">Imprimir</button>'
            '<script>window.addEventListener("load", function(){ window.print(); });</script>'
            '</main></body></html>'
        )

    def abbreviate(self, text, max_len=18):
        if not text:
            return ""
        text = str(text)
        if len(text) <= max_len:
            return text
        abbreviations = {
            "Contabilidade e Gestao": "Contab. Gestao",
            "Engenharia Informatica": "Eng. Informatica",
            "Enfermagem": "Enfermagem",
            "Agronomia": "Agronomia",
            "Direito": "Direito",
            "Economia": "Economia",
            "Medicina": "Medicina",
            "Funcionario": "Funcionario",
            "Visitante": "Visitante",
        }
        return abbreviations.get(text, text[:max_len - 2] + "..")

    def report_table_print_rows(self, reports, include_user=True):
        col_span = 9 if include_user else 8
        if not reports:
            return f'<tr><td colspan="{col_span}">Sem registos.</td></tr>'
        rows = []
        for report in reports:
            level = waiting_level(report.get("created_at"), report.get("status"))
            user_td = f'<td>{escape(self.abbreviate(USER_CATEGORY_LABELS.get(report.get("categoria_utilizador"), report.get("categoria_utilizador") or ""), 14))}</td>' if include_user else ""
            rows.append(
                f'<tr class="report-wait-{escape(level)}">'
                f'<td>#{report["id"]}</td>'
                f'<td>{format_datetime(report["created_at"])}</td>'
                f'<td>{escape(self.report_location_title(report))}</td>'
                f'<td>{escape(self.abbreviate(ISSUE_LABELS.get(report["issue_type"], report["issue_type"]), 16))}</td>'
                f'{user_td}'
                f'<td><span class="badge badge-status">{escape(STATUS_LABELS[report["status"]])}</span></td>'
                f'<td>{escape(self.wait_duration_label(report))}</td>'
                f'<td>{escape(self.resolution_duration_label(report))}</td>'
                f'<td>{escape(self.abbreviate(report.get("resolved_by_name") or report.get("started_by_name") or "", 16))}</td>'
                "</tr>"
            )
        return "\n".join(rows)

    def report_filters_summary(self, filters):
        labels = []
        if filters["date_from"]:
            labels.append(f"Desde {filters['date_from']}")
        if filters["date_to"]:
            labels.append(f"Ate {filters['date_to']}")
        if filters["subcategoria_local"]:
            labels.append(f"Local: {filters['subcategoria_local']}")
        elif filters["categoria_local"] != "all":
            labels.append(f"Categoria: {LOCAL_CATEGORY_LABELS.get(filters['categoria_local'], filters['categoria_local'])}")
        if filters["status"] != "all":
            labels.append(f"Estado: {STATUS_LABELS.get(filters['status'], filters['status'])}")
        if filters["curso"] != "all":
            labels.append(f"Curso: {filters['curso']}")
        if filters["periodo"] != "all":
            labels.append(f"Periodo: {PERIOD_LABELS.get(filters['periodo'], filters['periodo'])}")
        return " | ".join(labels) if labels else "Todos os registos"

    def print_report(self, report_id):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        report = next((item for item in database.filtered_reports("all", "all") if item["id"] == report_id), None)
        if not report:
            return self.not_found()
        return self.html_response(self.printable_report_html(report))

    def print_filtered_reports(self, query, auto_print=False):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        filters = self.admin_filters_from_query(query)
        reports = self.reports_for_filters(filters)
        stats = self.dashboard_stats(reports)
        monthly = self.monthly_stats(reports)

        by_category = self.count_by_category(reports)
        by_issue = self.count_by_issue(reports)
        by_status = self.count_by_status(reports)
        by_period = self.count_by_period(reports)
        by_month = self.count_by_month(reports)

        user_counts = {
            "student": sum(1 for r in reports if r.get("categoria_utilizador") == "student"),
            "employee": sum(1 for r in reports if r.get("categoria_utilizador") == "employee"),
            "visitor": sum(1 for r in reports if r.get("categoria_utilizador") == "visitor"),
        }

        body = render_template(
            "admin_report_print.html",
            institution_name=escape("Instituicao Kimpa Vita"),
            issued_at=escape(format_datetime(datetime.now())),
            period_summary=escape(self.report_filters_summary(filters)),
            generated_by=escape("Administrador"),
            total_count=len(reports),
            pending_count=stats["pending_count"],
            in_progress_count=stats["in_progress_count"],
            resolved_count=stats["resolved_count"],
            canceled_count=sum(1 for r in reports if r["status"] == "canceled"),
            resolution_rate=escape(self.resolution_rate(reports)),
            avg_wait_time=escape(stats["avg_wait_time"]),
            avg_resolution_time=escape(stats["avg_resolution_time"]),
            student_count=user_counts["student"],
            employee_count=user_counts["employee"],
            visitor_count=user_counts["visitor"],
            morning_count=by_period[0][1] if by_period else 0,
            afternoon_count=by_period[1][1] if len(by_period) > 1 else 0,
            night_count=by_period[2][1] if len(by_period) > 2 else 0,
            top_location=escape(self.top_location(reports)),
            top_issue=escape(self.top_issue(reports)),
            table_rows=self.report_table_print_rows(reports),
            analysis_html=self.generate_analysis(reports, by_category, by_period, by_month, stats),
            conclusions_html=self.generate_conclusions(reports, by_category, by_period, stats),
            auto_print_script="<script>window.addEventListener('load', function(){ setTimeout(function(){ window.print(); }, 300); });</script>" if auto_print else "",
            chart_payload=json.dumps(
                {
                    "byMonth": self.chart_rows(by_month),
                    "byIssue": self.chart_rows(by_issue),
                    "byStatus": self.chart_rows(by_status),
                    "byPeriod": self.chart_rows(by_period),
                }
            ),
        )
        return self.html_response(body)

    def export_filtered_reports_excel(self, query):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        filters = self.admin_filters_from_query(query)
        reports = self.reports_for_filters(filters)
        rows = self.report_table_print_rows(reports, include_photos=False)
        html = (
            '<html><head><meta charset="utf-8"></head><body>'
            f'<h1>Relatorio administrativo</h1><p>{escape(self.report_filters_summary(filters))}</p>'
            '<table border="1"><thead><tr>'
            '<th>ID</th><th>Data</th><th>Local</th><th>Categoria</th><th>Utilizador</th>'
            '<th>Curso</th><th>Periodo</th><th>Estado</th><th>Tempo de Espera</th>'
            '<th>Tempo de Resolucao</th><th>Resolvido Por</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></body></html>'
        )
        data = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/vnd.ms-excel; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="relatorios-filtrados.xls"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def show_monthly_report(self, query, auto_print=False):
        if not auth.valid_admin_cookie(self.headers):
            return self.redirect("/admin")
        month = clean_text((query.get("month") or [datetime.now().strftime("%Y-%m")])[0], 7)
        if not re.fullmatch(r"\d{4}-\d{2}", month):
            month = datetime.now().strftime("%Y-%m")
        reports = database.monthly_reports(month)
        stats = self.dashboard_stats(reports)
        by_category = self.count_by_category(reports)
        by_issue = self.count_by_issue(reports)
        by_status = self.count_by_status(reports)
        by_period = self.count_by_period(reports)
        by_month = self.count_by_month(reports)
        user_counts = {
            "student": sum(1 for r in reports if r.get("categoria_utilizador") == "student"),
            "employee": sum(1 for r in reports if r.get("categoria_utilizador") == "employee"),
            "visitor": sum(1 for r in reports if r.get("categoria_utilizador") == "visitor"),
        }
        false_alert_count = sum(1 for r in reports if r.get("falso_alerta"))
        body = render_template(
            "monthly_report.html",
            institution_name=escape("Instituicao Kimpa Vita"),
            issued_at=escape(format_datetime(datetime.now())),
            month=escape(month),
            generated_by=escape("Administrador"),
            total_count=len(reports),
            resolved_count=stats["resolved_count"],
            pending_count=stats["pending_count"],
            in_progress_count=stats["in_progress_count"],
            false_alert_count=false_alert_count,
            resolution_rate=escape(self.resolution_rate(reports)),
            avg_wait_time=escape(stats["avg_wait_time"]),
            avg_resolution_time=escape(stats["avg_resolution_time"]),
            top_location=escape(self.top_location(reports)),
            top_issue=escape(self.top_issue(reports)),
            top_period=escape(self.top_period(reports)),
            table_rows=self.report_table_print_rows(reports),
            analysis_html=self.generate_analysis(reports, by_category, by_period, by_month, stats),
            conclusions_html=self.generate_conclusions(reports, by_category, by_period, stats),
            auto_print_script="<script>window.addEventListener('load', function(){ setTimeout(function(){ window.print(); }, 300); });</script>" if auto_print else "",
            chart_payload=json.dumps(
                {
                    "byMonth": self.chart_rows(by_month),
                    "byIssue": self.chart_rows(by_issue),
                    "byStatus": self.chart_rows(by_status),
                    "byPeriod": self.chart_rows(by_period),
                }
            ),
        )
        return self.html_response(body)

    def simple_pdf(self, title, lines):
        text_lines = [title, ""] + lines
        y = 780
        commands = ["BT", "/F1 14 Tf"]
        for line in text_lines:
            safe = str(line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append(f"1 0 0 1 50 {y} Tm ({safe}) Tj")
            y -= 22
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        ]
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, 1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
        xref = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        pdf.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii"))
        return bytes(pdf)

    def monthly_report_pdf(self, query):
        return self.show_monthly_report(query, auto_print=True)
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

    def view_photo(self, query):
        report_id = clean_text((query.get("id") or [""])[0], 20)
        photo_type = clean_text((query.get("type") or [""])[0], 20)
        if not report_id or not photo_type or photo_type not in {"occurrence", "resolution"}:
            return self.redirect("/admin")
        report = next((item for item in database.filtered_reports("all", "all") if item["id"] == int(report_id)), None)
        if not report:
            return self.redirect("/admin")
        if photo_type == "occurrence":
            photo_url = report.get("foto_reporte")
        else:
            photo_url = report.get("foto_resolucao")
        if not photo_url:
            return self.redirect("/admin")
        body = render_template(
            "view_photo.html",
            report_id=report["id"],
            photo_url=escape(photo_url),
            photo_type=escape(photo_type),
            report_date=escape(format_datetime(report["created_at"])),
            report_location=escape(self.report_location_title(report)),
            report_category=escape(LOCAL_CATEGORY_LABELS.get(report.get("categoria_local"), report.get("categoria_local") or "")),
            report_status=escape(STATUS_LABELS[report["status"]]),
        )
        return self.html_response(body)

    def photo_grid_rows(self, reports):
        rows = []
        rows.append('<table class="photo-evidence-table"><thead><tr><th>ID</th><th>Ocorrencia</th><th>Resolucao</th></tr></thead><tbody>')
        for report in reports:
            occ_img = ''
            res_img = ''
            if report.get("foto_reporte"):
                occ_img = f'<img src="{escape(report["foto_reporte"])}" alt="Ocorrencia #{report["id"]}" class="evidence-thumb" loading="lazy" />'
            else:
                occ_img = '<span class="no-photo">Sem foto</span>'
            if report.get("foto_resolucao"):
                res_img = f'<img src="{escape(report["foto_resolucao"])}" alt="Resolucao #{report["id"]}" class="evidence-thumb" loading="lazy" />'
            else:
                res_img = '<span class="no-photo">Sem foto</span>'
            rows.append(f'<tr><td>#{report["id"]}</td><td class="evidence-cell">{occ_img}</td><td class="evidence-cell">{res_img}</td></tr>')
        rows.append('</tbody></table>')
        return "\n".join(rows)

    def generate_analysis(self, reports, by_category, by_period, by_month, stats):
        lines = []
        if by_category:
            top_cat = max(by_category, key=lambda item: item[1])
            lines.append(f"A categoria <strong>{escape(top_cat[0])}</strong> foi a mais reportada com {top_cat[1]} ocorrencia(s).")
        if by_period:
            top_period = max(by_period, key=lambda item: item[1])
            lines.append(f"O periodo da <strong>{escape(top_period[0].lower())}</strong> apresentou o maior numero de ocorrencias registadas ({top_period[1]}).")
        if stats["avg_wait_time"] and stats["avg_wait_time"] != "Ainda sem dados":
            lines.append(f"O tempo medio de espera foi de <strong>{escape(stats['avg_wait_time'])}</strong>.")
        if stats["avg_resolution_time"] and stats["avg_resolution_time"] != "Ainda sem dados":
            lines.append(f"O tempo medio de resolucao foi de <strong>{escape(stats['avg_resolution_time'])}</strong>.")
        if by_month and len(by_month) >= 2:
            first = by_month[0][1]
            last = by_month[-1][1]
            if last > first:
                lines.append("Verifica-se uma tendencia de <strong>crescimento</strong> nas ocorrencias nos ultimos meses.")
            elif last < first:
                lines.append("Verifica-se uma tendencia de <strong>reducao</strong> nas ocorrencias nos ultimos meses.")
        return "<br/>".join(lines) if lines else "Sem dados suficientes para analise."

    def generate_conclusions(self, reports, by_category, by_period, stats):
        issues = []
        if by_category:
            top_cat = max(by_category, key=lambda item: item[1])
            issues.append(f"Categoria mais critica: {top_cat[0]} ({top_cat[1]} ocorrencias)")
        if by_period:
            top_period = max(by_period, key=lambda item: item[1])
            issues.append(f"Periodo mais critico: {top_period[0]} ({top_period[1]} ocorrencias)")
        if stats["avg_wait_time"] and stats["avg_wait_time"] != "Ainda sem dados":
            issues.append(f"Tempo medio de espera elevado: {stats['avg_wait_time']}")
        if stats["resolution_rate"] and stats["resolution_rate"] != "0%":
            try:
                rate_num = int(stats["resolution_rate"].replace("%", ""))
                if rate_num < 70:
                    issues.append(f"Taxa de resolucao abaixo do ideal: {stats['resolution_rate']}")
            except ValueError:
                pass
        return "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in issues) + "</ul>" if issues else "<p>Sem observacoes relevantes.</p>"

    def top_location(self, reports):
        counts = {}
        for report in reports:
            key = self.report_location_title(report)
            counts[key] = counts.get(key, 0) + 1
        if not counts:
            return "Sem dados"
        return max(counts.items(), key=lambda item: item[1])[0]

    def top_issue(self, reports):
        counts = {}
        for report in reports:
            key = ISSUE_LABELS.get(report["issue_type"], report["issue_type"])
            counts[key] = counts.get(key, 0) + 1
        if not counts:
            return "Sem dados"
        return max(counts.items(), key=lambda item: item[1])[0]

    def top_period(self, reports):
        counts = {"Manha": 0, "Tarde": 0, "Noite": 0}
        for report in reports:
            period = get_period(report.get("created_at"))
            label = PERIOD_LABELS.get(period, "Manha")
            counts[label] = counts.get(label, 0) + 1
        top = max(counts.items(), key=lambda item: item[1])
        return top[0] if top[1] > 0 else "Sem dados"

    def redirect(self, location):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def not_found(self):
        self.html_response("<h1>Pagina nao encontrada</h1>", HTTPStatus.NOT_FOUND)
