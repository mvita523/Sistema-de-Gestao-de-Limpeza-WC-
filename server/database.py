"""
Modulo de acesso a base de dados PostgreSQL.

Fornece funcoes para inicializar a base de dados, executar limpezas periodicas,
gerir utilizadores de limpeza, criar e filtrar reportes, alterar estados de ocorrencias,
obter estatisticas e enviar notificacoes.
"""

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


# ==========================================================
# Ligacao a base de dados
# ==========================================================

def connect():
    """Estabelece uma ligacao a base de dados PostgreSQL.

    Returns:
        psycopg2.connection: Objeto de ligacao ativa a base de dados.
    """
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


# ==========================================================
# Inicializacao e manutencao da base de dados
# ==========================================================

def init_database():
    """Inicializa a base de dados executando o esquema definido em schema.sql.

    A inicializacao e apenas executada se a variavel AUTO_INIT_DATABASE estiver ativa.
    Cria todas as tabelas, indices e dados iniciais definidos no ficheiro de schema.
    """
    if not AUTO_INIT_DATABASE:
        logger.info("database_init_skipped")
        return
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(schema_sql)
    logger.info("database_init_completed")


def cleanup_old_reports():
    """Remove reportes antigos e sessoes expiradas da base de dados.

    Elimina reportes com idade superior a REPORT_RETENTION_DAYS e todas as sessoes
    de utilizadores de limpeza cujo token tenha expirado. Executado periodicamente
    por uma tarefa agendada em background.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            deleted_count = 0
            if REPORT_RETENTION_DAYS > 0:
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
    """Inicia uma thread daemon que executa a limpeza periodica da base de dados.

    A limpeza e executada a cada CLEANUP_INTERVAL_SECONDS segundos.
    """
    def run_cleanup_loop():
        while True:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                cleanup_old_reports()
            except Exception:
                logger.exception("cleanup_failed")

    threading.Thread(target=run_cleanup_loop, daemon=True).start()


# ==========================================================
# Gestao de locais
# ==========================================================

def get_locations():
    """Obtem a lista completa de locais ordenada por edificio, piso e nome.

    Returns:
        list: Lista de dicionarios com id, name, building, floor, created_at.
    """
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


def get_location(location_id):
    """Obtem um local pelo seu identificador.

    Args:
        location_id (int): Identificador unico do local.

    Returns:
        dict: Dados do local (id, name, building, floor) ou None.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, building, floor FROM locations WHERE id = %s", (location_id,))
            return cursor.fetchone()


def get_max_location_id():
    """Obtem o maior identificador de local existente na base de dados.

    Returns:
        int: Maior ID de local ou 1 se nao existirem locais.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COALESCE(MAX(id), 1) AS max_id FROM locations")
            return cursor.fetchone()["max_id"]


# ==========================================================
# Gestao de utilizadores de limpeza
# ==========================================================

def list_cleaning_users():
    """Obtem a lista completa de utilizadores de limpeza ordenada por data de criacao.

    Returns:
        list: Lista de dicionarios com id, name, username, email, receives_notifications,
              active, created_at.
    """
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
    """Cria um novo utilizador de limpeza na base de dados.

    Args:
        name (str): Nome completo do utilizador.
        username (str): Nome de utilizador unico (minusculas).
        email (str): Endereco de email ou vazio.
        password (str): Palavra-passe em texto (sera hashificada antes de armazenar).
    """
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
    """Atualiza o email e a preferencia de notificacao de um utilizador.

    Args:
        user_id (int): Identificador do utilizador.
        email (str): Novo endereco de email.
        receives_notifications (bool): Se o utilizador deve receber notificacoes.
    """
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


def update_cleaning_user(user_id, name, username, email, password, receives_notifications):
    """Atualiza os dados do utilizador de limpeza.

    Args:
        user_id (int): Identificador do utilizador.
        name (str): Novo nome do utilizador.
        username (str): Novo username.
        email (str): Novo email.
        password (str): Nova palavra-passe em texto; nenhum update se vazio.
        receives_notifications (bool): Se o utilizador deve receber notificacoes.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            if password:
                cursor.execute(
                    """
                    UPDATE cleaning_users
                    SET name = %s, username = %s, email = %s, password_hash = %s, receives_notifications = %s
                    WHERE id = %s
                    """,
                    (name, username, email, auth.hash_password(password), receives_notifications, user_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE cleaning_users
                    SET name = %s, username = %s, email = %s, receives_notifications = %s
                    WHERE id = %s
                    """,
                    (name, username, email, receives_notifications, user_id),
                )


def update_cleaning_user(user_id, name, username, email, receives_notifications, password=None):
    with connect() as connection:
        with connection.cursor() as cursor:
            if password:
                cursor.execute(
                    """
                    UPDATE cleaning_users
                    SET name = %s, username = %s, email = %s, receives_notifications = %s, password_hash = %s
                    WHERE id = %s
                    """,
                    (name, username, email, receives_notifications, auth.hash_password(password), user_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE cleaning_users
                    SET name = %s, username = %s, email = %s, receives_notifications = %s
                    WHERE id = %s
                    """,
                    (name, username, email, receives_notifications, user_id),
                )


def delete_cleaning_user(user_id):
    """Remove um utilizador de limpeza da base de dados.

    Args:
        user_id (int): Identificador do utilizador a eliminar.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM cleaning_users WHERE id = %s", (user_id,))


def find_cleaning_user(username):
    """Procura um utilizador de limpeza pelo nome de utilizador.

    Args:
        username (str): Nome de utilizador a procurar.

    Returns:
        dict: Dados do utilizador (id, name, username, password_hash, active) ou None.
    """
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


# ==========================================================
# Sessoes de utilizadores de limpeza
# ==========================================================

def create_cleaner_session(user_id):
    """Cria uma nova sessao para um utilizador de limpeza.

    Gera um token seguro, remove sessoes antigas do mesmo utilizador e cria a nova
    sessao com validade de CLEANER_SESSION_DAYS dias.

    Args:
        user_id (int): Identificador do utilizador.

    Returns:
        str: Token de sessao gerado.
    """
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
    """Obtem os dados do utilizador associado a um token de sessao.

    Args:
        token (str): Token de sessao a validar.

    Returns:
        dict: Dados do utilizador (id, name, username, email) ou None se invalido/expirado.
    """
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
    """Remove uma sessao de utilizador pelo seu token.

    Args:
        token (str): Token de sessao a remover.
    """
    if not token:
        return
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM cleaning_sessions WHERE token = %s", (token,))


# ==========================================================
# Consultas SQL - Reportes
# ==========================================================

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
    """Insere um novo reporte de ocorrencia na base de dados.

    Args:
        issue_type (str): Tipo de problema reportado.
        description (str): Descricao detalhada do problema.
        categoria_utilizador (str): Categoria do utilizador que reportou.
        foto_reporte (str): Caminho para a foto da ocorrencia.
        categoria_local (str): Categoria do local afetado.
        subcategoria_local (str): Subcategoria/local especifico.
        curso (str): Curso do utilizador.
        periodo (str): Periodo (manha/tarde/noite).
        location_id (int, optional): Identificador do local.

    Returns:
        int: Identificador do reporte criado.
    """
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


def filtered_reports(
    status,
    location_id,
    categoria_local=None,
    subcategoria_local=None,
    periodo=None,
    resolved_by_name=None,
    issue_type=None,
    curso=None,
    date_from=None,
    date_to=None,
):
    """Consulta reportes com filtros opcionais dinamicos.

    Constroi a clausula WHERE com base nos filtros fornecidos e realiza um JOIN
    com as tabelas de locais e utilizadores de limpeza para obter nomes de
    responsaveis e iniciadores.

    Args:
        status (str): Estado do reporte (pending, in_progress, resolved, canceled ou all).
        location_id (str/int): Identificador do local ou "all".
        categoria_local (str, optional): Categoria do local.
        subcategoria_local (str, optional): Subcategoria/local especifico.
        periodo (str, optional): Periodo (morning, afternoon, night).
        resolved_by_name (str, optional): Nome parcial do funcionario que resolveu.
        issue_type (str, optional): Tipo de problema.
        curso (str, optional): Curso do utilizador.
        date_from (str, optional): Data inicial no formato YYYY-MM-DD.
        date_to (str, optional): Data final no formato YYYY-MM-DD.

    Returns:
        list: Lista de reportes que correspondem aos filtros aplicados.
    """
    values = []
    where = []
    if status in {"pending", "in_progress", "resolved", "canceled"}:
        where.append("r.status = %s")
        values.append(status)
    if str(location_id).isdigit():
        where.append("r.location_id = %s")
        values.append(int(location_id))
    if categoria_local:
        where.append("r.categoria_local = %s")
        values.append(categoria_local)
    if subcategoria_local:
        where.append("r.subcategoria_local = %s")
        values.append(subcategoria_local)
    if periodo:
        where.append("r.periodo = %s")
        values.append(periodo)
    if resolved_by_name:
        where.append("u.name ILIKE %s")
        values.append(f"%{resolved_by_name}%")
    if issue_type:
        where.append("r.issue_type = %s")
        values.append(issue_type)
    if curso:
        where.append("r.curso = %s")
        values.append(curso)
    if date_from:
        where.append("r.created_at >= %s::date")
        values.append(date_from)
    if date_to:
        where.append("r.created_at < (%s::date + INTERVAL '1 day')")
        values.append(date_to)
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT r.id, r.location_id, r.issue_type, r.description, r.status,
                       r.created_at, r.started_at, r.resolved_at, r.student_number,
                       r.categoria_utilizador, r.foto_reporte, r.categoria_local,
                       r.subcategoria_local, r.curso, r.periodo, r.falso_alerta,
                       r.foto_resolucao,
                       l.name AS location_name, l.building, l.floor,
                       u.name AS resolved_by_name,
                       su.name AS started_by_name
                FROM reports r
                LEFT JOIN locations l ON l.id = r.location_id
                LEFT JOIN cleaning_users u ON u.id = r.resolved_by_id
                LEFT JOIN cleaning_users su ON su.id = r.started_by_id
                {where_sql}
                ORDER BY r.created_at DESC
                """,
                values,
            )
            return cursor.fetchall()


def get_cleaner_reports(cleaner_id):
    """Obtem reportes visiveis para um funcionario de limpeza.

    Inclui todos os relatorios pendentes (disponiveis para qualquer funcionario)
    mais os relatorios que o funcionario iniciou em resolucao ou resolveu
    (incluindo falsos alertas).

    Args:
        cleaner_id (int): Identificador do funcionario de limpeza.

    Returns:
        list: Lista de reportes com o mesmo formato de filtered_reports.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.id, r.location_id, r.issue_type, r.description, r.status,
                       r.created_at, r.started_at, r.resolved_at, r.student_number,
                       r.categoria_utilizador, r.foto_reporte, r.categoria_local,
                       r.subcategoria_local, r.curso, r.periodo, r.falso_alerta,
                       r.foto_resolucao,
                       l.name AS location_name, l.building, l.floor,
                       u.name AS resolved_by_name,
                       su.name AS started_by_name
                FROM reports r
                LEFT JOIN locations l ON l.id = r.location_id
                LEFT JOIN cleaning_users u ON u.id = r.resolved_by_id
                LEFT JOIN cleaning_users su ON su.id = r.started_by_id
                WHERE r.status = 'pending' OR r.started_by_id = %s OR r.resolved_by_id = %s
                ORDER BY r.created_at DESC
                """,
                (cleaner_id, cleaner_id),
            )
            return cursor.fetchall()


# ==========================================================
# Gestao de estados de reportes
# ==========================================================

def start_report(report_id, started_by_id=None):
    """Marca um reporte como "em resolucao".

    Args:
        report_id (int): Identificador do reporte.
        started_by_id (int, optional): Identificador do funcionario que iniciou.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'in_progress',
                    started_at = COALESCE(started_at, NOW()),
                    started_by_id = COALESCE(started_by_id, %s)
                WHERE id = %s AND status = 'pending'
                """,
                (started_by_id, report_id),
            )


def resolve_report(report_id, resolved_by_id=None, foto_resolucao=None):
    """Marca um reporte como "resolvido".

    Atualiza o estado, define o momento de resolucao e guarda a foto de resolucao.

    Args:
        report_id (int): Identificador do reporte.
        resolved_by_id (int, optional): Identificador do funcionario que resolveu.
        foto_resolucao (str, optional): Caminho para a foto de resolucao.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'resolved',
                    falso_alerta = FALSE,
                    started_at = COALESCE(started_at, NOW()),
                    started_by_id = COALESCE(started_by_id, %s),
                    resolved_at = COALESCE(resolved_at, NOW()),
                    resolved_by_id = %s,
                    foto_resolucao = COALESCE(%s, foto_resolucao)
                WHERE id = %s
                """,
                (resolved_by_id, resolved_by_id, foto_resolucao, report_id),
            )


def cancel_report(report_id):
    """Cancela um reporte, marcando-o como falso alerta.

    Args:
        report_id (int): Identificador do reporte a cancelar.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'canceled',
                    falso_alerta = TRUE,
                    started_at = COALESCE(started_at, NOW()),
                    resolved_at = COALESCE(resolved_at, NOW())
                WHERE id = %s
                """,
                (report_id,),
            )


def mark_false_alert(report_id, cleaner_id, foto_resolucao=None):
    """Marca um reporte como falso alerta.

    Args:
        report_id (int): Identificador do reporte.
        cleaner_id (int): Identificador do funcionario que registou o falso alerta.
        foto_resolucao (str, optional): Caminho para foto de evidencia.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE reports
                SET status = 'canceled',
                    falso_alerta = TRUE,
                    started_at = COALESCE(started_at, NOW()),
                    started_by_id = COALESCE(started_by_id, %s),
                    resolved_at = COALESCE(resolved_at, NOW()),
                    resolved_by_id = %s,
                    foto_resolucao = COALESCE(%s, foto_resolucao)
                WHERE id = %s
                """,
                (cleaner_id, cleaner_id, foto_resolucao, report_id),
            )


# ==========================================================
# Configuracoes da aplicacao
# ==========================================================

def get_setting(key, default_value=""):
    """Obtem o valor de uma configuracao da aplicacao.

    Args:
        key (str): Chave da configuracao.
        default_value (str): Valor por defeito se a configuracao nao existir.

    Returns:
        str: Valor da configuracao.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT value FROM app_settings WHERE key = %s", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default_value


def set_setting(key, value):
    """Define ou atualiza uma configuracao da aplicacao.

    Args:
        key (str): Chave da configuracao.
        value (str): Valor a guardar.
    """
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


# ==========================================================
# Notificacoes e emails
# ==========================================================

def get_cleaner_notification_emails():
    """Obtem a lista de emails dos utilizadores de limpeza com notificacoes ativas.

    Filtra apenas utilizadores ativos, com notificacoes ativadas e com email valido.

    Returns:
        list: Lista de enderecos de email.
    """
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


# ==========================================================
# Calculo de estatisticas
# ==========================================================

def count_resolved_by_cleaner(cleaner_id):
    """Conta o numero de reportes resolvidos por um funcionario.

    Args:
        cleaner_id (int): Identificador do funcionario.

    Returns:
        int: Numero de reportes resolvidos.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS total FROM reports WHERE status = 'resolved' AND resolved_by_id = %s",
                (cleaner_id,),
            )
            row = cursor.fetchone()
            return row["total"] if row else 0


def count_false_alerts_by_cleaner(cleaner_id):
    """Conta o numero de falsos alertas registados por um funcionario.

    Args:
        cleaner_id (int): Identificador do funcionario.

    Returns:
        int: Numero de falsos alertas.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS total FROM reports WHERE falso_alerta = TRUE AND resolved_by_id = %s",
                (cleaner_id,),
            )
            row = cursor.fetchone()
            return row["total"] if row else 0


# ==========================================================
# Relatorios mensais
# ==========================================================

def monthly_reports(month):
    """Obtem todos os reportes de um mes especifico.

    Args:
        month (str): Mes no formato YYYY-MM.

    Returns:
        list: Lista de reportes do mes com dados de resolucao e nomes de utilizadores.
    """
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.id, r.issue_type, r.description, r.status, r.created_at,
                       r.started_at, r.resolved_at, r.categoria_local,
                       r.subcategoria_local, r.periodo, r.falso_alerta,
                       u.name AS resolved_by_name,
                       su.name AS started_by_name
                FROM reports r
                LEFT JOIN cleaning_users u ON u.id = r.resolved_by_id
                LEFT JOIN cleaning_users su ON su.id = r.started_by_id
                WHERE date_trunc('month', r.created_at) = %s::date
                ORDER BY r.created_at DESC
                """,
                (f"{month}-01",),
            )
            return cursor.fetchall()
