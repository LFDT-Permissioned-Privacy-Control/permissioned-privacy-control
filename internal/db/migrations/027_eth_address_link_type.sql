-- Add link_type to eth_address_links.
-- 'user' = user-initiated (signed challenge), 'system' = auto-linked when tx submitted through proxy.
--
-- Also:
--   - Make signature and message_hash nullable (system links have no signature).
--   - Change UNIQUE(eth_address) → UNIQUE(did, eth_address) so multiple DIDs can link
--     the same address (e.g. shared deployer key used by two users).

ALTER TABLE eth_address_links
    ALTER COLUMN signature DROP NOT NULL,
    ALTER COLUMN message_hash DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS link_type TEXT NOT NULL DEFAULT 'user'
        CHECK (link_type IN ('user', 'system'));

-- Replace address-level unique constraint with (did, address) uniqueness.
ALTER TABLE eth_address_links DROP CONSTRAINT IF EXISTS eth_address_links_eth_address_key;
ALTER TABLE eth_address_links ADD CONSTRAINT eth_address_links_did_eth_address_key
    UNIQUE (did, eth_address);

---- create above / drop below ----

ALTER TABLE eth_address_links DROP CONSTRAINT IF EXISTS eth_address_links_did_eth_address_key;
ALTER TABLE eth_address_links ADD CONSTRAINT eth_address_links_eth_address_key UNIQUE (eth_address);
ALTER TABLE eth_address_links DROP COLUMN IF EXISTS link_type;
ALTER TABLE eth_address_links ALTER COLUMN signature SET NOT NULL;
ALTER TABLE eth_address_links ALTER COLUMN message_hash SET NOT NULL;
