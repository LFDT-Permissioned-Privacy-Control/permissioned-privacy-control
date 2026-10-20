-- 019_price_change_audit_and_ip_tracking.sql
-- Price manipulation protection: audit log + IP tracking

CREATE TABLE price_change_log (
    id            SERIAL PRIMARY KEY,
    api_key_id    VARCHAR(36) NOT NULL,
    api_key_name  VARCHAR(255) NOT NULL,
    token_address VARCHAR(42) NOT NULL,
    symbol        VARCHAR(20) NOT NULL,
    old_price     DOUBLE PRECISION,
    new_price     DOUBLE PRECISION NOT NULL,
    deviation_pct DOUBLE PRECISION,
    ip_address    VARCHAR(45) NOT NULL,
    ip_changed    BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pcl_created_at ON price_change_log(created_at DESC);
CREATE INDEX idx_pcl_api_key_id ON price_change_log(api_key_id);

ALTER TABLE api_keys ADD COLUMN last_ip VARCHAR(45);

---- create above / drop below ----
