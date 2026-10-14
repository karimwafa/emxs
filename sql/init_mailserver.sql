-- EMXS Mail Server Database Schema (PostgreSQL 14+)
-- Database: mailserver | Owner: mailuser

-- 1. Virtual Domains
CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Virtual Mail Accounts
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    quota_bytes BIGINT NOT NULL DEFAULT 10737418240, -- 10 GB default
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    send_only BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Virtual Aliases & Forwarders
CREATE TABLE IF NOT EXISTS aliases (
    id SERIAL PRIMARY KEY,
    domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    source VARCHAR(255) NOT NULL UNIQUE,
    destination TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. DKIM Signing Keys
CREATE TABLE IF NOT EXISTS dkim_keys (
    id SERIAL PRIMARY KEY,
    domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    selector VARCHAR(50) NOT NULL DEFAULT 'mail',
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    dns_record TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Dashboard Administrators & 2FA / TOTP
CREATE TABLE IF NOT EXISTS dashboard_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin',
    otp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    otp_secret VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

-- 6. Dashboard Sessions
CREATE TABLE IF NOT EXISTS dashboard_sessions (
    id SERIAL PRIMARY KEY,
    token VARCHAR(128) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    ip_address VARCHAR(64),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Email Transactions (30-day Retention History)
CREATE TABLE IF NOT EXISTS email_transactions (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_id VARCHAR(255),
    sender VARCHAR(255) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    subject TEXT,
    status VARCHAR(50) NOT NULL,
    direction VARCHAR(20) NOT NULL,
    client_ip VARCHAR(64),
    size_bytes BIGINT DEFAULT 0,
    spam_score NUMERIC(5,2) DEFAULT 0.0,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for high-performance querying
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);
CREATE INDEX IF NOT EXISTS idx_aliases_source ON aliases(source);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token ON dashboard_sessions(token);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expires ON dashboard_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_email_trans_ts ON email_transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_email_trans_msgid ON email_transactions(message_id);
CREATE INDEX IF NOT EXISTS idx_email_trans_sender ON email_transactions(sender);
CREATE INDEX IF NOT EXISTS idx_email_trans_recipient ON email_transactions(recipient);
CREATE INDEX IF NOT EXISTS idx_email_trans_status ON email_transactions(status);

-- Grant permissions to mailuser
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mailuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mailuser;
