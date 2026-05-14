# Sistema de Gestao de Limpeza de WC

MVP web para reportes em tempo real via QR Code. Estudantes abrem `/report?location_id=ID`, reportam problemas sem login, e administradores acompanham tudo no dashboard.

## Stack

- Backend: Python
- Frontend: HTML renderizado no servidor
- Estilos: CSS
- Base de dados: PostgreSQL, gerivel no pgAdmin
- Driver PostgreSQL: `psycopg2-binary`
- Notificacoes: `print` no servidor e email opcional por Gmail para o administrador
- Admin: token simples via `ADMIN_TOKEN`

## Estrutura

```txt
server/app.py
templates/
static/styles.css
database/schema.sql
requirements.txt
```

## Preparar a base de dados

1. Criar uma base PostgreSQL no pgAdmin, por exemplo `wc_cleaning`.
2. Executar o script [database/schema.sql](database/schema.sql) nessa base de dados.

## Como correr

Instalar a dependencia Python para ligar ao PostgreSQL:

```bash
pip install -r requirements.txt
```

```bash
python server/app.py
```

No Windows, tambem podes usar:

```bash
py server/app.py
```

Variaveis opcionais:

```env
PORT=4000
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/wc_cleaning
ADMIN_TOKEN=change-me
```

Podes criar um ficheiro `server/.env` com esses valores. Ajusta o utilizador, password e nome da base para ficarem iguais ao que tens no pgAdmin:

```env
PORT=4000
DATABASE_URL=postgresql://postgres:A_TUA_PASSWORD@localhost:5432/wc_cleaning
ADMIN_TOKEN=change-me
```

## Notificacoes por Gmail

O sistema pode enviar email quando um reporte e criado. A implementacao usa Gmail SMTP sem dependencias Python extra.

No ficheiro `server/.env`, adiciona:

```env
GMAIL_ADDRESS=o_teu_email@gmail.com
GMAIL_APP_PASSWORD=a_tua_app_password
ADMIN_EMAIL=email_do_administrador@gmail.com
```

No Gmail, usa uma App Password, nao a password normal da conta. Se estes campos nao estiverem preenchidos, a app continua a funcionar sem email.

O admin pode gerir varios destinatarios na seccao `Utilizadores da limpeza`: cada responsavel da limpeza tem um email e a opcao `Recebe notificacoes`. Quando um novo reporte e criado, o sistema envia a notificacao para todos os utilizadores ativos que tenham essa opcao ligada.

O `ADMIN_EMAIL` fica como fallback: se nenhum utilizador da limpeza tiver email de notificacao ativo, o sistema envia para esse email.

O administrador pode alterar o email que recebe notificacoes no dashboard ou via API:

```http
PATCH /api/admin/notification-email
Authorization: Bearer change-me
Content-Type: application/json

{
  "notification_email": "novo.admin@gmail.com"
}
```

Para consultar o email atual:

```http
GET /api/admin/notification-email
Authorization: Bearer change-me
```

Enderecos principais:

- Reporte: `http://localhost:4000/report?location_id=1`
- Admin: `http://localhost:4000/admin`
- Limpeza: `http://localhost:4000/cleaner`
- Healthcheck: `http://localhost:4000/health`

No dashboard, introduzir o token definido em `ADMIN_TOKEN`. Se nao for definido, o token por defeito e `change-me`.

## Utilizadores da limpeza

O administrador gere os responsaveis da limpeza no dashboard admin. Na seccao `Utilizadores da limpeza`, pode criar utilizadores com nome, utilizador, email e palavra-passe, editar os emails que recebem notificacoes, ou eliminar utilizadores existentes.

Os responsaveis da limpeza entram em:

```txt
http://localhost:4000/cleaner
```

Depois do login, veem apenas os reportes pendentes e podem marcar cada reporte como resolvido. Esta area nao permite gerir emails, estatisticas ou utilizadores.

## Logica do QR Code

Cada WC recebe um QR Code com um link unico:

```txt
https://dominio-da-universidade.pt/report?location_id=1
```

A pagina le `location_id` da URL no servidor e mostra a localizacao correspondente.

## Anti-spam simples

O servidor bloqueia novos envios durante 60 segundos para o mesmo par IP/localizacao.

## Limpeza automatica

Os reportes criados pelo formulario sao eliminados automaticamente quando tiverem mais de 15 dias. Isto limpa os dados guardados em `reports`, incluindo numero do WC, tipo de problema, comentario, estado e datas. As localizacoes dos WC ficam preservadas.
