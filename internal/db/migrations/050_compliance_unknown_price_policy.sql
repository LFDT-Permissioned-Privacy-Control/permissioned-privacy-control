-- Add unknown_price_policy to compliance_config
ALTER TABLE compliance_config
ADD COLUMN unknown_price_policy TEXT NOT NULL DEFAULT 'forbidden'
CHECK (unknown_price_policy IN ('allowed', 'forbidden'));
