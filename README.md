# Sistema de Gestao de Limpeza WC

Aplicacao Python simples para reportar problemas em WC, gerir reportes no dashboard admin e permitir que a equipa de limpeza marque reportes como resolvidos.

## Stack Tecnologica

### Bibliotecas Padrao do Python
- `http.server.ThreadingHTTPServer` e `http.server.BaseHTTPRequestHandler` - Servidor HTTP thread-safe para tratar multiplos pedidos em paralelo sem dependencias externas.
- `threading` - Agendamento de tarefas periodicas em background (limpeza de reportes antigos).
- `secrets` - Geracao de tokens criptograficamente seguros para sessoes, CSRF e salt de passwords.
- `hashlib` e `hmac` - Hashing de passwords com PBKDF2-SHA256 e assinatura HMAC-SHA256 de tokens.
- `base64` - Codificacao e descodificacao de payloads de tokens assinados (base64 URL-safe).
- `json` - Serializacao e desserializacao de payloads e dados da aplicacao.
- `re` - Validacao de entradas, parsing de rotas e processamento de formularios.
- `datetime` - Formatacao, calculo de duracoes e classificacao de periodos do dia.
- `email.parser.BytesParser` e `email.policy` - Parsing de formularios multipart/form-data para upload de imagens.
- `http.cookies.SimpleCookie` - Processamento de cookies HTTP para sessoes e CSRF.
- `logging` - Logging estruturado da aplicacao.
- `os` e `pathlib.Path` - Gestao de variaveis de ambiente e caminhos de ficheiros.
- `urllib.parse` - Parsing de URLs, query strings e redirecionamentos.

### Bibliotecas Externas
- `psycopg2-binary` (via `psycopg2`) - Driver PostgreSQL para ligacao a base de dados Supabase/PostgreSQL. Usa `RealDictCursor` para retornar resultados como dicionarios.
- `python-dotenv` (via `dotenv.load_dotenv`) - Carregamento automatico de variaveis de ambiente a partir de `server/.env`.
- `requests` - Cliente HTTP para envio de notificacoes por email via API Brevo.

## Estrutura do Projeto

```
Sistema-de-Gestao-de-Limpeza-WC/
├── server/
│   ├── __init__.py          # Pacote Python vazio
│   ├── app.py               # Ponto de entrada: inicializa DB, scheduler e servidor
│   ├── config.py            # Configuracoes globais, variaveis de ambiente e logging
│   ├── auth.py              # Modulo de autenticacao: hash de passwords, tokens assinados, CSRF, sessoes
│   ├── handlers.py          # AppHandler: rotas GET/POST/PATCH, renderizacao HTML, validacoes
│   ├── database.py          # Acesso a base de dados: CRUD de reportes, utilizadores, sessoes e estatisticas
│   ├── utils.py             # Utilitarios: validacoes, formatacao, render_template, rate limiter
│   └── email_service.py     # Servico de notificacoes por email via API Brevo
├── database/
│   └── schema.sql           # Schema PostgreSQL idempotente com tabelas, indices e dados iniciais
├── templates/
│   ├── admin.html           # Dashboard admin com graficos, filtros, tabelas e modal de utilizadores
│   ├── report.html          # Formulario publico de reporte de ocorrencias
│   ├── success.html         # Pagina de confirmacao apos submissao de reporte
│   ├── admin_login.html     # Formulario de login do administrador
│   ├── cleaner_login.html   # Formulario de login dos funcionarios de limpeza
│   ├── cleaner_dashboard.html # Dashboard do funcionario de limpeza
│   └── monthly_report.html  # Relatorio mensal formatado
├── static/
│   ├── styles.css           # Estilos CSS da aplicacao
│   └── uploads/             # Diretorio para armazenamento de fotos submetidas
├── requirements.txt         # Dependencias Python
├── .env.example             # Exemplo de ficheiro de variaveis de ambiente
├── Procfile                 # Configuracao para deploy no Render
├── start.sh                 # Script de arranque local
└── README.md                # Documentacao do projeto
```

## Configuracao

Crie um ficheiro local `server/.env` a partir de `.env.example` ou configure as variaveis diretamente no Render:

```env
DATABASE_URL=postgresql://user:password@host:5432/postgres?sslmode=require
ADMIN_TOKEN=change_this_to_random_secret
GMAIL_ADDRESS=
GMAIL_APP_PASSWORD=
ADMIN_EMAIL=
PORT=4000
AUTO_INIT_DATABASE=true
BREVO_API_KEY=
REPORT_RETENTION_DAYS=0
CLEANER_SESSION_DAYS=7
CSRF_TOKEN_SECONDS=7200
ADMIN_SESSION_SECONDS=28800
SPAM_WINDOW_SECONDS=60
SPAM_MAX_ATTEMPTS=3
FORM_MAX_BYTES=8388608
UPLOAD_MAX_BYTES=5242880
CLEANUP_INTERVAL_SECONDS=86400
LOG_LEVEL=INFO
```

`DATABASE_URL` e `ADMIN_TOKEN` sao obrigatorios. A aplicacao falha no arranque se estiverem ausentes. Se o URL PostgreSQL nao tiver `sslmode`, a aplicacao adiciona `sslmode=require` automaticamente.

### Variaveis de Ambiente Disponiveis

| Variavel | Descricao | Padrao | Obrigatoria |
|----------|-----------|--------|-------------|
| `DATABASE_URL` | URL de ligacao PostgreSQL (Supabase ou outro) | - | Sim |
| `ADMIN_TOKEN` | Token secreto para acesso a area admin e APIs protegidas | - | Sim |
| `PORT` | Porta do servidor HTTP | 4000 | Nao |
| `AUTO_INIT_DATABASE` | Inicializar schema automaticamente no arranque | true | Nao |
| `REPORT_RETENTION_DAYS` | Dias de retencao de reportes (0 = nunca apagar) | 0 | Nao |
| `CLEANER_SESSION_DAYS` | Validade das sessoes de funcionarios de limpeza | 7 | Nao |
| `CSRF_TOKEN_SECONDS` | Validade dos tokens CSRF | 7200 | Nao |
| `ADMIN_SESSION_SECONDS` | Validade das sessoes de administrador | 28800 | Nao |
| `SPAM_WINDOW_SECONDS` | Janela de tempo para rate limiting | 60 | Nao |
| `SPAM_MAX_ATTEMPTS` | Maximo de submissoes por IP/local na janela | 3 | Nao |
| `FORM_MAX_BYTES` | Tamanho maximo de formularios | 8388608 | Nao |
| `UPLOAD_MAX_BYTES` | Tamanho maximo de upload de imagens | 5242880 | Nao |
| `CLEANUP_INTERVAL_SECONDS` | Intervalo entre limpezas de dados antigos | 86400 | Nao |
| `LOG_LEVEL` | Nivel de logging (DEBUG, INFO, WARNING, ERROR) | INFO | Nao |
| `BREVO_API_KEY` | Chave API Brevo para envio de notificacoes por email | - | Nao |
| `ADMIN_EMAIL` | Email de notificacao admin por defeito | - | Nao |

## Uso Local

```bash
pip install -r requirements.txt
python server/app.py
```

A aplicacao fica em `http://localhost:4000` por padrao. Nota: os cookies sao emitidos com `Secure`, como exigido para deploy; em browsers locais por HTTP, login pode exigir HTTPS ou ajuste temporario de desenvolvimento.

## Supabase

1. Crie um projeto Supabase.
2. Copie o connection string PostgreSQL.
3. Defina `DATABASE_URL` com `sslmode=require`.
4. Com `AUTO_INIT_DATABASE=true`, o schema idempotente em `database/schema.sql` cria tabelas, indices e dados iniciais se ainda nao existirem.

O schema usa `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS` e `ON CONFLICT DO NOTHING`, evitando operacoes destrutivas repetidas.

## Deploy no Render

Configure um Web Service com:

- Build Command: `pip install -r requirements.txt`
- Start Command: `python server/app.py`

Ou use o `Procfile` incluido:

```text
web: python server/app.py
```

Variaveis obrigatorias no Render:

- `DATABASE_URL`
- `ADMIN_TOKEN`
- `PORT` e definido pelo Render automaticamente

Variaveis opcionais:

- `BREVO_API_KEY`
- `ADMIN_EMAIL`
- `AUTO_INIT_DATABASE`
- `REPORT_RETENTION_DAYS`
- Todas as variaveis de configuracao listadas acima

## Endpoints

### Publicos
- `GET /` - Redireciona para `/report`
- `GET /report` - Formulario publico de reporte de ocorrencias
- `POST /report` - Submissao de novo reporte com foto opcional
- `GET /health` - Health check JSON (retorna `{"ok": true}`)
- `GET /static/styles.css` - Ficheiro CSS
- `GET /static/uploads/<filename>` - Acesso a fotos submetidas
- `GET /view-photo?path=<path>` - Visualizacao de fotos

### Administrador
- `GET /admin` - Dashboard admin com graficos, filtros, tabela de reportes e gestao de utilizadores
- `POST /admin/login` - Login do administrador (token bearer via formulario)
- `POST /admin/logout` - Logout do administrador
- `GET /admin/monthly-report?month=YYYY-MM` - Relatorio mensal HTML
- `GET /admin/monthly-report.pdf?month=YYYY-MM` - Exportacao de relatorio mensal em PDF
- `GET /admin/reports/print?<filters>` - Visualizacao de impressao de reportes filtrados
- `GET /admin/reports/export-pdf?<filters>` - Exportacao de reportes filtrados em PDF
- `GET /admin/reports/export-excel?<filters>` - Exportacao de reportes filtrados em Excel
- `POST /admin/reports/<id>/start` - Marcar reporte como "em resolucao"
- `POST /admin/reports/<id>/resolve` - Marcar reporte como "resolvido"
- `POST /admin/reports/<id>/cancel` - Marcar reporte como "falso alerta"
- `POST /admin/cleaning-users` - Criar utilizador de limpeza
- `POST /admin/cleaning-users/<id>/update` - Atualizar utilizador de limpeza
- `POST /admin/cleaning-users/<id>/delete` - Eliminar utilizador de limpeza
- `POST /admin/notification-email` - Atualizar email de notificacao
- `PATCH /api/admin/notification-email` - API para atualizar email de notificacao via JSON
- `GET /api/admin/notification-email` - API para obter email de notificacao (requer Bearer token)
- `GET /admin/reports/<id>/print` - Impressao de reporte individual

### Funcionarios de Limpeza
- `GET /cleaner` - Dashboard do funcionario de limpeza
- `POST /cleaner/login` - Login do funcionario
- `POST /cleaner/logout` - Logout do funcionario
- `POST /cleaner/reports/<id>/start` - Marcar reporte como "em resolucao"
- `POST /cleaner/reports/<id>/resolve` - Marcar reporte como "resolvido" com foto de evidencia
- `POST /cleaner/reports/<id>/false-alert` - Marcar reporte como "falso alerta" com foto de evidencia

## Funcionalidades Principais

### Reporte Publico
- Formulario com selecao de tipo de problema (sem papel higienico, sem sabonete, WC sujo, mau cheiro, falta de agua, outro)
- Categorizacao de local (WC, Sala de Aula, Gabinete) com subcategorias dinamicas
- Periodo do dia (manha, tarde, noite)
- Curso do utilizador (Engenharia Informatica, Contabilidade e Gestao, Agronomia, Enfermagem, Direito, Economia, Medicina, Funcionario, Visitante)
- Upload de foto do reporte (JPG, PNG, WEBP, max 5MB)
- Rate limiting por IP e local (3 submissoes por minuto por local)
- Validacao completa de entradas com escape HTML para prevencao XSS

### Dashboard Admin
- KPIs em tempo real: total, pendentes, em resolucao, resolvidos, taxa de resolucao, falsos alertas
- Graficos interativos (Canvas 2D nativo): ocorrencias por mes, reportes por dia, problemas reportados, notificacoes por categoria, estados dos relatorios, relatorios por periodo
- Top 5 funcionarios por reports resolvidos
- Filtros avancados: status, local, categoria, subcategoria, tipo de problema, curso, periodo, intervalo de datas
- Pesquisa instantanea e ordenacao por colunas na tabela de reportes
- Paginacao client-side (12 reportes por pagina)
- Impressao e exportacao PDF/Excel de reportes filtrados
- Relatorio mensal com exportacao PDF
- Gestao completa de utilizadores de limpeza (CRUD, toggle de notificacoes, password toggle)
- Modal de fotos do relatorio (ocorrencia + resolucao)
- Responsivo com adaptacao para ecras pequenos

### Dashboard Funcionario de Limpeza
- Lista de ocorrencias atribuidas (pendentes acessiveis a todos, iniciadas/resolvidas pelo proprio funcionario)
- Contadores: pendentes, em resolucao, resolvidos, falsos alertas
- Acoes: marcar como em resolucao, resolver com foto de evidencia, marcar como falso alerta
- Visualizacao de fotos da ocorrencia e resolucao
- Classificacao visual por tempo de espera (recente <24h, aviso 24-72h, atrasado >72h)
- Linhas coloridas por estado e atraso

### Sistema de Notificacoes
- Envio automatico de email a novos reportes via API Brevo
- Destinatarios: funcionarios de limpeza com notificacoes ativadas, ou email admin por defeito
- Configuracao de email de notificacao via interface admin ou API
- Verificacao de estado de envio atraves de logs

### Seguranca
- Hash de passwords com PBKDF2-SHA256, 210.000 iteracoes e salt unico
- Tokens de sessao admin assinados com HMAC-SHA256 e expiracao
- Tokens de sessao de limpeza armazenados na base de dados com expiracao
- Protecao CSRF em formularios autenticados (tokens assinados com expiracao de 2 horas)
- Cookies `HttpOnly`, `Secure`, `SameSite=Lax` e `Path=/`
- Rate limiting por IP e local para prevencao de spam
- Validacao rigorosa de emails, usernames, passwords, descricoes, localizacoes e periodo
- Escape HTML em todas as saidas para prevencao de XSS
- Headers de seguranca: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy` restritiva, HSTS quando HTTPS
- Prepared statements com placeholders `%s` em todas as queries SQL (protecao contra SQL injection)
- Logging estruturado sem expor passwords, tokens ou connection strings
- Autorizacao granular: rotas de admin exigem cookie de sessao, APIs usam Bearer token

## Base de Dados

### Tabelas Principais

| Tabela | Descricao |
|--------|-----------|
| `locations` | Locais fisicos do edificio (WC, salas, gabinetes) com edificio e piso |
| `reports` | Reportes de ocorrencias com estado, fotos, timestamps e responsaveis |
| `cleaning_users` | Funcionarios de limpeza com credenciais hasheadas e preferencias de notificacao |
| `cleaning_sessions` | Sessoes ativas de funcionarios com token e expiracao |
| `app_settings` | Configuracoes da aplicacao (email de notificacao) |

### Indices
- `idx_reports_created_at` - Otimiza consultas por data de criacao
- `idx_reports_status` - Otimiza filtros por estado
- `idx_reports_location_id` - Otimiza consultas por local
- `idx_reports_started_at` - Otimiza calculos de tempo de espera
- `idx_reports_resolved_at` - Otimiza calculos de tempo de resolucao
- `idx_cleaning_sessions_user_id` - Otimiza busca de sessoes por utilizador
- `idx_cleaning_sessions_expires_at` - Otimiza limpeza de sessoes expiradas

### Retencao de Dados
- `REPORT_RETENTION_DAYS` controla a idade maxima dos reportes. Reportes mais antigos sao removidos automaticamente.
- A limpeza executa-se a cada `CLEANUP_INTERVAL_SECONDS` (padrao: 24 horas) numa thread daemon.
- Sessoes de limpeza expiradas sao removidas em cada ciclo de limpeza.

## Dados Iniciais

O schema inclui localizacoes pre-configuradas:
- WC Biblioteca - Masculino (Biblioteca, piso 0)
- WC Biblioteca - Feminino (Biblioteca, piso 0)
- WC Engenharia - Piso 1 (Edificio de Engenharia, piso 1)
- WC Cantina (Cantina, piso 0)
