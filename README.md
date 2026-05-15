# Sistema de Gestao de Limpeza WC

Aplicacao Python simples para reportar problemas em WC, gerir reportes no dashboard admin e permitir que a equipa de limpeza marque reportes como resolvidos.

## Stack

- Python com `ThreadingHTTPServer` e `BaseHTTPRequestHandler`
- PostgreSQL/Supabase via `psycopg2-binary`
- Templates HTML estaticos
- Gmail SMTP opcional para notificacoes

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
```

`DATABASE_URL` e `ADMIN_TOKEN` sao obrigatorios. A aplicacao falha no arranque se estiverem ausentes. Se o URL PostgreSQL nao tiver `sslmode`, a aplicacao adiciona `sslmode=require` automaticamente.

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

- `GMAIL_ADDRESS`
- `GMAIL_APP_PASSWORD`
- `ADMIN_EMAIL`
- `AUTO_INIT_DATABASE`
- `REPORT_RETENTION_DAYS`

## Endpoints

- `/report`: formulario publico de reporte
- `/admin`: dashboard admin
- `/cleaner`: area da limpeza
- `/health`: health check JSON
- `/api/admin/notification-email`: API protegida por bearer token admin

## Seguranca

- Sem credenciais hardcoded no codigo.
- `DATABASE_URL` e `ADMIN_TOKEN` sao obrigatorios.
- Cookies `HttpOnly`, `Secure`, `SameSite=Lax` e `Path=/`.
- Sessoes admin assinadas e com expiracao.
- Sessoes de limpeza guardadas na base de dados, com expiracao e rotacao por login.
- Protecao CSRF em login/logout e formularios autenticados.
- Rate limit por IP e localizacao para reportes publicos.
- Headers de seguranca: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy` e HSTS quando HTTPS.
- Validacao de emails, usernames, passwords, descricoes, localizacoes e numero de estudante.
- Logging estruturado sem expor passwords ou connection strings.

