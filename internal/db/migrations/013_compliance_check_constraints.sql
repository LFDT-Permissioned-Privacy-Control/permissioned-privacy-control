-- H6: Add CHECK constraints for positive amounts on compliance tables.

ALTER TABLE travel_rule_records ADD CONSTRAINT chk_travel_rule_amount_usd_positive CHECK (amount_usd > 0);
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_usd_positive CHECK (price_usd > 0);
ALTER TABLE compliance_config ADD CONSTRAINT chk_compliance_threshold_non_negative CHECK (threshold_usd >= 0);

---- create above / drop below ----

ALTER TABLE travel_rule_records DROP CONSTRAINT IF EXISTS chk_travel_rule_amount_usd_positive;
ALTER TABLE token_prices DROP CONSTRAINT IF EXISTS chk_token_price_usd_positive;
ALTER TABLE compliance_config DROP CONSTRAINT IF EXISTS chk_compliance_threshold_non_negative;
