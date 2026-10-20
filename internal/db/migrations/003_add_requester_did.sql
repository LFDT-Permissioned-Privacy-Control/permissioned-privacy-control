-- Add requester_did to disclosure_requests for DID-based access control
-- This allows block explorer to query grants by auditor's DID

ALTER TABLE disclosure_requests ADD COLUMN IF NOT EXISTS requester_did VARCHAR(255);

-- Index for looking up grants by requester DID
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_requester_did ON disclosure_requests(requester_did) WHERE requester_did IS NOT NULL;

---- create above / drop below ----

DROP INDEX IF EXISTS idx_disclosure_requests_requester_did;
ALTER TABLE disclosure_requests DROP COLUMN IF EXISTS requester_did;
