CREATE TABLE refresh_tokens (
    token_sha     TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    token_bcrypt  TEXT NOT NULL,
    expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    used          BOOLEAN DEFAULT FALSE,
    user_agent    TEXT NOT NULL,
    ip_address    TEXT NOT NULL,
    access_jti    TEXT NOT NULL
);