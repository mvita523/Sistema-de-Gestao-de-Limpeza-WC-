import logging
import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOAD_DIR = STATIC_DIR / "uploads"

LOCAL_ENV_PATH = BASE_DIR / "server" / ".env"
load_dotenv(LOCAL_ENV_PATH, override=False)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger("wc_cleaning")


def with_required_sslmode(database_url):
    parsed = urlsplit(database_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if "sslmode" not in query:
        query["sslmode"] = "require"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


_RAW_DATABASE_URL = os.environ["DATABASE_URL"].strip()
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"].strip()
if not _RAW_DATABASE_URL:
    raise RuntimeError("DATABASE_URL must not be empty")
if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN must not be empty")

DATABASE_URL = with_required_sslmode(_RAW_DATABASE_URL)
PORT = int(os.environ.get("PORT", "4000"))

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "").strip()
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")
DEFAULT_ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip()

AUTO_INIT_DATABASE = os.environ.get("AUTO_INIT_DATABASE", "true").lower() in {"1", "true", "yes"}
REPORT_RETENTION_DAYS = int(os.environ.get("REPORT_RETENTION_DAYS", "15"))
CLEANUP_INTERVAL_SECONDS = int(os.environ.get("CLEANUP_INTERVAL_SECONDS", str(24 * 60 * 60)))
CLEANER_SESSION_DAYS = int(os.environ.get("CLEANER_SESSION_DAYS", "7"))
CSRF_TOKEN_SECONDS = int(os.environ.get("CSRF_TOKEN_SECONDS", str(2 * 60 * 60)))
ADMIN_SESSION_SECONDS = int(os.environ.get("ADMIN_SESSION_SECONDS", str(8 * 60 * 60)))

SPAM_WINDOW_SECONDS = int(os.environ.get("SPAM_WINDOW_SECONDS", "60"))
SPAM_MAX_ATTEMPTS = int(os.environ.get("SPAM_MAX_ATTEMPTS", "3"))
FORM_MAX_BYTES = int(os.environ.get("FORM_MAX_BYTES", str(8 * 1024 * 1024)))
UPLOAD_MAX_BYTES = int(os.environ.get("UPLOAD_MAX_BYTES", str(5 * 1024 * 1024)))
