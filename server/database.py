import threading
import time
import secrets

import psycopg2
from psycopg2.extras import RealDictCursor

from . import auth
from .config import (
    AUTO_INIT_DATABASE,
    CLEANER_SESSION_DAYS,
    CLEANUP_INTERVAL_SECONDS,
    DATABASE_URL,
    REPORT_RETENTION_DAYS,
    SCHEMA_PATH,
    logger,
)


def connect():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_database():
    if not AUTO_INIT_DATABASE:
        logger.info("database_init_skipped")
        return
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(schema_sql)
    logger.info("database_init_completed")


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
            deleted_sessions = cursor.rowcount
    logger.info("cleanup_completed reports_deleted=%s sessions_deleted=%s", deleted_count, deleted_sessions)


def start_cleanup_scheduler():
    def run_cleanup_loop():
        while True:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                cleanup_old_reports()
            except Exception:
                logger.exception("cleanup_failed")

    threading.Thread(target=run_cleanup_loop, daemon=True).start()


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
                (name, username, email, auth.hash_password(password)),
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
            cursor.execute("DELETE FROM cleaning_sessions WHERE user_id = %s OR expires_at < NOW()", (user_id,))
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
                SELECT u.id, u.name, u.username, u.email
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
            cursor.execute("SELECT id, name, building, floor FROM locations WHERE id = %s", (location_id,))
            return cursor.fetchone()


def get_max_location_id():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COALESCE(MAX(id), 1) AS max_id FROM locations")
            return cursor.fetchone()["max_id"]


def create_report(
    issue_type,
    description,
    categoria_utilizador,
    foto_reporte,
    categoria_local,
    subcategoria_local,
    curso,
    periodo,
    location_id=None,
):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO reports (
                    location_id, issue_type, description, categoria_utilizador,
                    foto_reporte, categoria_local, subcategoria_local, curso, periodo
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    location_id,
                    issue_type,
                    description,
                    categoria_utilizador,
                    foto_reporte,
                    categoria_local,
                    subcategoria_local,
                    curso,
                    periodo,
                ),
            )
            return cursor.fetchone()["id"]


def filtered_reports(status, location_id):
    values = []
    where = []
    if status in {"pending", "resolved", "canceled"}:
        where.append("r.status = %s")
        values.append(status)
    if str(location_id).isdigit():
        where.append("r.location_id = %s")
        values.append(int(location_id))
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT r.id, r.location_id, r.issue_type, r.description, r.status,
                       r.created_at, r.resolved_at, r.student_number,
                       r.categoria_utilizador, r.foto_reporte, r.categoria_local,
                       r.subcategoria_local, r.curso, r.periodo, r.falso_alerta,
                       r.foto_resolucao,
                       l.name AS location_name, l.building, l.floor,
                       u.name AS resolved_by_name
                FROM reports r
                LEFT JOIN locations l ON l.id = r.location_id
                LEFT JOIN cleaning_users u ON u.id = r.resolved_by_id
                {where_sql}
                ORDER BY r.created_at DESC
                """,
                values,
            )
            return cursor.fetchall()


def resolve_report(report_id, resolved_by_id=None, foto_resolucao=None):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'resolved',
                    falso_alerta = FALSE,
                    resolved_at = COALESCE(resolved_at, NOW()),
                    resolved_by_id = %s,
                    foto_resolucao = COALESCE(%s, foto_resolucao)
                WHERE id = %s
                """,
                (resolved_by_id, foto_resolucao, report_id),
            )


def cancel_report(report_id):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'canceled',
                    falso_alerta = TRUE,
                    resolved_at = COALESCE(resolved_at, NOW())
                WHERE id = %s
                """,
                (report_id,),
            )


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
