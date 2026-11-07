package admissionsql

// Finance selection applies the complete predicate before the sentinel.
const financeQuery = `-- ONE data query inside the existing bounded READ ONLY REPEATABLE READ
-- transaction. Reuse bounded/begin/rollback; known successful COMMIT is required
-- before publishing the copied snapshot. No SQL is held across A rendering/audit.
-- $1 network_key bytea; $2 expected generation uuid; $3 expected coverage bytea;
-- $4 environment; $5 canonical chainID; $6 genesis bytea; $7 deploymentID;
-- $8 exact data-org uuid; $9 sorted unique target actor text[] (1..256);
-- $10 time.Unix(start,0).UTC(); $11 time.Unix(end,0).UTC(), both INCLUSIVE;
-- $12 true iff all-target-addresses; $13 sorted unique explicit bytea[] (1..1024)
-- or an empty NONNULL array in all-target-addresses mode.
-- Mode all-target-addresses adds no explicit address predicate after ORIGINAL
-- event actor selection. It does NOT infer current wallets or sender ownership.
-- In list mode, known root from OR to must match a literal. admission_only has
-- no known addresses and therefore never matches an explicit address list.
WITH gate AS MATERIALIZED (
 SELECT
  COALESCE((SELECT n.ready AND n.generation=$2::uuid AND n.coverage_digest=$3
     AND n.environment=$4 AND n.chain_id=$5 AND n.genesis_hash=$6 AND n.deployment_id=$7
    FROM ops_admission_v2.network_state n WHERE n.network_key=$1),false)
  AND (SELECT count(*)=2 AND bool_and(c.relkind='r' AND c.relpersistence='p'
     AND NOT c.relispartition AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ops_admission_v2'
      AND c.relname IN('network_state','compliance_events')) AS ok
)
SELECT gate.ok,e.present,e.valid_shape,e.id,e.tx_hash,e.actor_id,e.org_id,e.kind,e.coverage,
 e.from_address,e.to_address,e.token,e.amount_wei,e.amount_fiat,e.threshold_fiat,
 e.currency,e.decision,e.monitored,e.reason,e.record_id,e.decision_at,e.policy_digest,
 e.quote_digest,e.quote_id,e.quote_source,e.quote_value,e.quote_as_of,e.quote_observed_at,
 e.anchor_hash,e.anchor_number,e.anchor_timestamp,e.evidence_profile
FROM gate
LEFT JOIN LATERAL (
 SELECT true AS present,
  COALESCE(octet_length(tx_hash)=32 AND octet_length(actor_id) BETWEEN 1 AND 128
   AND octet_length(kind) BETWEEN 1 AND 32 AND octet_length(coverage) BETWEEN 1 AND 32
   AND (from_address IS NULL OR octet_length(from_address)=20)
   AND (to_address IS NULL OR octet_length(to_address)=20)
   AND (token IS NULL OR octet_length(token)=20)
   AND (amount_wei IS NULL OR octet_length(amount_wei)<=78)
   AND (currency IS NULL OR octet_length(currency)<=3)
   AND octet_length(decision) BETWEEN 1 AND 7 AND octet_length(reason)<=2048
   AND octet_length(policy_digest)=32
   AND (quote_digest IS NULL OR octet_length(quote_digest)=32)
   AND (quote_id IS NULL OR octet_length(quote_id)<=100)
   AND (quote_source IS NULL OR octet_length(quote_source)<=128)
   AND octet_length(anchor_hash)=32 AND octet_length(evidence_profile) BETWEEN 1 AND 128,false) AS valid_shape,
  id,
  CASE WHEN octet_length(tx_hash)=32 THEN tx_hash END AS tx_hash,
  CASE WHEN octet_length(actor_id)<=128 THEN actor_id END AS actor_id,
  org_id::text AS org_id,
  CASE WHEN octet_length(kind)<=32 THEN kind END AS kind,
  CASE WHEN octet_length(coverage)<=32 THEN coverage END AS coverage,
  CASE WHEN from_address IS NULL OR octet_length(from_address)=20 THEN from_address END AS from_address,
  CASE WHEN to_address IS NULL OR octet_length(to_address)=20 THEN to_address END AS to_address,
  CASE WHEN token IS NULL OR octet_length(token)=20 THEN token END AS token,
  CASE WHEN amount_wei IS NULL OR octet_length(amount_wei)<=78 THEN amount_wei END AS amount_wei,
  CASE WHEN amount_fiat IS NULL THEN NULL WHEN amount_fiat>=0 AND amount_fiat<1e100 AND scale(amount_fiat)<=400 THEN amount_fiat::text ELSE 'invalid' END AS amount_fiat,
  CASE WHEN threshold_fiat IS NULL THEN NULL WHEN threshold_fiat>=0 AND threshold_fiat<1e100 AND scale(threshold_fiat)<=400 THEN threshold_fiat::text ELSE 'invalid' END AS threshold_fiat,
  CASE WHEN currency IS NULL OR octet_length(currency)<=3 THEN currency END AS currency,
  CASE WHEN octet_length(decision)<=7 THEN decision END AS decision,
  monitored,
  CASE WHEN octet_length(reason)<=2048 THEN reason END AS reason,
  record_id::text AS record_id,decision_at,
  CASE WHEN octet_length(policy_digest)=32 THEN policy_digest END AS policy_digest,
  CASE WHEN quote_digest IS NULL OR octet_length(quote_digest)=32 THEN quote_digest END AS quote_digest,
  CASE WHEN quote_id IS NULL OR octet_length(quote_id)<=100 THEN quote_id END AS quote_id,
  CASE WHEN quote_source IS NULL OR octet_length(quote_source)<=128 THEN quote_source END AS quote_source,
  CASE WHEN quote_value IS NULL THEN NULL WHEN quote_value>0 AND quote_value<1e12 AND scale(quote_value)<=400 THEN quote_value::text ELSE 'invalid' END AS quote_value,
  quote_as_of,quote_observed_at,
  CASE WHEN octet_length(anchor_hash)=32 THEN anchor_hash END AS anchor_hash,
	  CASE WHEN anchor_number>=0 AND anchor_number<=18446744073709551615 AND scale(anchor_number)=0 THEN anchor_number::text ELSE 'invalid' END AS anchor_number,
	  CASE WHEN anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615 AND scale(anchor_timestamp)=0 THEN anchor_timestamp::text ELSE 'invalid' END AS anchor_timestamp,
  CASE WHEN octet_length(evidence_profile)<=128 THEN evidence_profile END AS evidence_profile
 FROM ops_admission_v2.compliance_events
 WHERE gate.ok AND network_key=$1 AND org_id=$8::uuid AND actor_id=ANY($9::text[])
  AND decision_at >= $10::timestamptz AND decision_at <= $11::timestamptz
  AND ($12::boolean OR from_address=ANY($13::bytea[]) OR to_address=ANY($13::bytea[]))
 ORDER BY decision_at DESC,id DESC LIMIT 101
) e ON true
ORDER BY e.decision_at DESC NULLS LAST,e.id DESC NULLS LAST;

-- A false gate is Unavailable even if no events exist. A true gate + NULL
-- present is an authoritative ZERO RETAINED scoped rows only. For present=true,
-- decode nullable SQL projection fields, require every original mandatory field,
-- preserve actual optional NULLs, then reuse Event.Valid/canonical money/quote
-- validation. NULL generated by an oversize guard is NEVER silently accepted as
-- a previously optional absence: see required raw optional-shape checks below.
-- To distinguish absent from rejected optional input, production MUST additionally
-- scan the bounded valid_shape boolean in the LATERAL row, requiring all
-- original fixed/optional byte lengths before projection. On false, reject
-- Unavailable before constructing Event. This marker is not a public Verified flag.
-- No SELECT of travel_records, PII JSON, user tables, current price or chain state.
-- LIMIT101 follows ALL predicates. Collect at most100 valid rows; row101 is
-- TooBroad, no truncation. Canonical source/evidence order is actual id ASC in Go
-- AFTER proving the full retained set <=100, reusing compliance_org_page for SQL.
`
