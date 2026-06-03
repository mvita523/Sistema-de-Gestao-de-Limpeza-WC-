"""
Ponto de entrada da aplicacao de gestao de limpeza WC.

Inicializa a base de dados, executa limpeza de reportes antigos,
inicia o agendador de limpeza periodica e arranca o servidor HTTP.
"""

import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from server.config import PORT, logger
    from server.database import cleanup_old_reports, init_database, start_cleanup_scheduler
    from server.handlers import AppHandler
else:
    from .config import PORT, logger
    from .database import cleanup_old_reports, init_database, start_cleanup_scheduler
    from .handlers import AppHandler


def main():
    """Inicia o servidor HTTP da aplicacao.

    Executa as operacoes de inicializacao e arranca o servidor em modo threading
    para tratar multiplos pedidos em paralelo.
    """
    logger.info("startup_begin")
    init_database()
    cleanup_old_reports()
    start_cleanup_scheduler()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), AppHandler)
    logger.info("startup_complete host=0.0.0.0 port=%s", PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
