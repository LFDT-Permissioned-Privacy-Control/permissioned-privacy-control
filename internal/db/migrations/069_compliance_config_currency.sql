-- 069_compliance_config_currency.sql
--
-- WHAT:  Adds a per-org `currency` column to compliance_config.
--
-- WHY:   RD-1158. The compliance base currency was a single cluster-wide
--        system_setting (`base_currency`), so switching it re-valued EVERY
--        org's travel-rule threshold at once. A tier-2 org admin could pick a
--        currency for which other orgs' tokens have no price and thereby
--        fail-close those orgs' transfers — which is why commit 8ce16e2
--        (Audit C5) locked the GLOBAL switch to super-admin only. Making
--        currency per-org removes that cross-org blast radius entirely: each
--        org values its transfers in its own currency, so a tier-2 org admin
--        can set it for their own org with no effect on any other tenant.
--
-- AFFECTED: every existing compliance_config row is defaulted to currency='usd'
--        (the prior implicit global default). No threshold conversion is done —
--        an org's existing threshold_fiat NUMBER is now read as USD until the
--        org explicitly changes its currency. Detection query for rows already
--        on a non-default currency (none expected at apply time):
--          SELECT org_id, currency FROM compliance_config WHERE currency <> 'usd';
--
-- EXPAND-ONLY: additive column with a safe NOT NULL DEFAULT; no data rewrite,
--        no DROP. The CHECK mirrors compliance.IsValidCurrency (usd/eur/chf/
--        gbp/aed); all existing rows are 'usd' so the constraint validates.
--
-- AUTHORITATIVE RECORD: this migration file (git) + PR review + tern
--        schema_version (applied-at). No audit-table write from a migration.

ALTER TABLE compliance_config
    ADD COLUMN IF NOT EXISTS currency VARCHAR(10) NOT NULL DEFAULT 'usd'
        CHECK (currency IN ('usd', 'eur', 'chf', 'gbp', 'aed'));
