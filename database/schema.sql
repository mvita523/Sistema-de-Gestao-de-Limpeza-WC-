DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issue_type') THEN
    CREATE TYPE issue_type AS ENUM ('paper', 'soap', 'dirty', 'smell', 'other');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'report_status') THEN
    CREATE TYPE report_status AS ENUM ('pending', 'resolved');
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS locations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  building VARCHAR(120) NOT NULL,
  floor VARCHAR(40) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
  issue_type issue_type NOT NULL,
  description TEXT,
  status report_status NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(80) PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cleaning_users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  username VARCHAR(80) NOT NULL UNIQUE,
  email VARCHAR(180),
  password_hash TEXT NOT NULL,
  receives_notifications BOOLEAN NOT NULL DEFAULT TRUE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE cleaning_users
  ADD COLUMN IF NOT EXISTS email VARCHAR(180);

ALTER TABLE cleaning_users
  ADD COLUMN IF NOT EXISTS receives_notifications BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS student_number VARCHAR(80);

ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS resolved_by_id INTEGER REFERENCES cleaning_users(id);

CREATE TABLE IF NOT EXISTS cleaning_sessions (
  token VARCHAR(128) PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES cleaning_users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_location_id ON reports(location_id);
CREATE INDEX IF NOT EXISTS idx_cleaning_sessions_user_id ON cleaning_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_cleaning_sessions_expires_at ON cleaning_sessions(expires_at);

INSERT INTO locations (id, name, building, floor)
VALUES
  (1, 'WC Biblioteca - Masculino', 'Biblioteca', '0'),
  (2, 'WC Biblioteca - Feminino', 'Biblioteca', '0'),
  (3, 'WC Engenharia - Piso 1', 'Edificio de Engenharia', '1'),
  (4, 'WC Cantina', 'Cantina', '0')
ON CONFLICT (id) DO NOTHING;

SELECT setval('locations_id_seq', COALESCE((SELECT MAX(id) FROM locations), 1), true);
