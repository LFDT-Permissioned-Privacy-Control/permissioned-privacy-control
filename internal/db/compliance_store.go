package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"privacy-proxy/internal/compliance"
)

// Compliance Config operations

func (d *DB) GetComplianceConfig(ctx context.Context, orgID string) (*compliance.ComplianceConfig, error) {
	query := `SELECT id, org_id, enabled, threshold_fiat, unknown_price_policy, enforcement_mode, currency, created_at, updated_at
	          FROM compliance_config WHERE org_id = $1`

	config := &compliance.ComplianceConfig{}
	err := d.conn.QueryRowContext(ctx, query, orgID).Scan(
		&config.ID, &config.OrgID, &config.Enabled, &config.ThresholdFiat, &config.UnknownPricePolicy,
		&config.EnforcementMode, &config.Currency, &config.CreatedAt, &config.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance config: %w", err)
	}
	return config, nil
}

func (d *DB) UpsertComplianceConfig(ctx context.Context, config *compliance.ComplianceConfig) error {
	// enforcement_mode is NOT NULL with a CHECK(enforce|monitor). Coalesce an
	// unset value to the safe default so no caller can trip the constraint or
	// silently persist an empty mode.
	mode := config.EnforcementMode
	if mode == "" {
		mode = compliance.EnforcementEnforce
	}

	// RD-1111: unknown_price_policy is NOT NULL with a CHECK(allowed|forbidden).
	// Coalesce an unset value to the fail-closed default ("forbidden") so no
	// caller can trip the constraint with an empty string (which surfaced as a
	// raw 500 on the first PUT for a new org). Defaulting here — not relying on
	// the column DEFAULT — because we always bind $5 explicitly. "forbidden" is
	// the safe choice: an unknown price BLOCKS the transfer.
	pricePolicy := config.UnknownPricePolicy
	if pricePolicy == "" {
		pricePolicy = compliance.UnknownPriceForbidden
	}

	// RD-1158: currency is NOT NULL with a CHECK(usd|eur|chf|gbp|aed). Coalesce an
	// unset value to "usd" (the prior implicit global default) so no caller can
	// trip the constraint with an empty string.
	currency := config.Currency
	if currency == "" {
		currency = "usd"
	}

	query := `INSERT INTO compliance_config (id, org_id, enabled, threshold_fiat, unknown_price_policy, enforcement_mode, currency)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          ON CONFLICT (org_id) DO UPDATE SET
	          enabled = EXCLUDED.enabled,
	          threshold_fiat = EXCLUDED.threshold_fiat,
	          unknown_price_policy = EXCLUDED.unknown_price_policy,
	          enforcement_mode = EXCLUDED.enforcement_mode,
	          currency = EXCLUDED.currency,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	config.EnforcementMode = mode
	config.UnknownPricePolicy = pricePolicy
	config.Currency = currency
	return d.conn.QueryRowContext(ctx, query,
		config.ID, config.OrgID, config.Enabled, config.ThresholdFiat, pricePolicy, mode, currency,
	).Scan(&config.CreatedAt, &config.UpdatedAt)
}

// System Token Price operations

func (d *DB) GetSystemTokenPrice(ctx context.Context, coingeckoID string) (*compliance.SystemTokenPrice, error) {
	query := `SELECT id, coingecko_id, symbol, decimals, price_fiat, source, token_address, prices_by_currency, updated_at
	          FROM system_token_prices WHERE coingecko_id = $1`

	sp := &compliance.SystemTokenPrice{}
	var coingecko sql.NullString
	var tokenAddr sql.NullString
	var pricesJSON []byte
	err := d.conn.QueryRowContext(ctx, query, coingeckoID).Scan(
		&sp.ID, &coingecko, &sp.Symbol, &sp.Decimals, &sp.PriceFiat, &sp.Source, &tokenAddr, &pricesJSON, &sp.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get system token price: %w", err)
	}
	if coingecko.Valid {
		sp.CoingeckoID = &coingecko.String
	}
	if tokenAddr.Valid {
		sp.TokenAddress = &tokenAddr.String
	}
	if len(pricesJSON) > 0 {
		if err := json.Unmarshal(pricesJSON, &sp.PricesByCurrency); err != nil {
			slog.Warn("corrupt prices_by_currency JSON for system price", "symbol", sp.Symbol, "error", err)
		}
	}
	return sp, nil
}

func (d *DB) UpsertSystemTokenPrice(ctx context.Context, price *compliance.SystemTokenPrice) error {
	pricesJSON, err := json.Marshal(price.PricesByCurrency)
	if err != nil {
		return fmt.Errorf("failed to marshal prices_by_currency: %w", err)
	}

	query := `INSERT INTO system_token_prices (coingecko_id, symbol, decimals, price_fiat, source, token_address, prices_by_currency, updated_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	          ON CONFLICT (coingecko_id) WHERE coingecko_id IS NOT NULL DO UPDATE SET
	          symbol = EXCLUDED.symbol,
	          decimals = EXCLUDED.decimals,
	          price_fiat = EXCLUDED.price_fiat,
	          source = EXCLUDED.source,
	          token_address = EXCLUDED.token_address,
	          prices_by_currency = EXCLUDED.prices_by_currency,
	          updated_at = EXCLUDED.updated_at`

	_, err = d.conn.ExecContext(ctx, query,
		price.CoingeckoID, price.Symbol, price.Decimals, price.PriceFiat,
		price.Source, price.TokenAddress, pricesJSON, price.UpdatedAt,
	)
	return err
}

func (d *DB) ListSystemTokenPrices(ctx context.Context) ([]*compliance.SystemTokenPrice, error) {
	query := `SELECT id, coingecko_id, symbol, decimals, price_fiat, source, token_address, prices_by_currency, updated_at
	          FROM system_token_prices ORDER BY symbol`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list system token prices: %w", err)
	}
	defer rows.Close()

	var prices []*compliance.SystemTokenPrice
	for rows.Next() {
		sp := &compliance.SystemTokenPrice{}
		var coingecko sql.NullString
		var tokenAddr sql.NullString
		var pricesJSON []byte
		if err := rows.Scan(&sp.ID, &coingecko, &sp.Symbol, &sp.Decimals, &sp.PriceFiat, &sp.Source, &tokenAddr, &pricesJSON, &sp.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan system token price: %w", err)
		}
		if coingecko.Valid {
			sp.CoingeckoID = &coingecko.String
		}
		if tokenAddr.Valid {
			sp.TokenAddress = &tokenAddr.String
		}
		if len(pricesJSON) > 0 {
			if err := json.Unmarshal(pricesJSON, &sp.PricesByCurrency); err != nil {
			slog.Warn("corrupt prices_by_currency JSON for system price", "symbol", sp.Symbol, "error", err)
		}
		}
		prices = append(prices, sp)
	}
	return prices, rows.Err()
}

// Token Price operations

func (d *DB) GetTokenPrice(ctx context.Context, orgID, tokenAddress string) (*compliance.TokenPrice, error) {
	query := `SELECT id, org_id, token_address, symbol, decimals, price_fiat, coingecko_id, updated_by_user_id, prices_by_currency, created_at, updated_at
	          FROM token_prices WHERE org_id = $1 AND token_address = $2`

	return scanTokenPrice(d.conn.QueryRowContext(ctx, query, orgID, strings.ToLower(tokenAddress)))
}

// UpsertTokenPrice creates or updates a per-org token price.
// activeCurrency is the current base currency code (e.g. "usd") used to atomically
// resolve price_fiat from the merged prices_by_currency in SQL, avoiding TOCTOU races.
func (d *DB) UpsertTokenPrice(ctx context.Context, price *compliance.TokenPrice, activeCurrency string) error {
	pricesByCurrency, err := json.Marshal(price.PricesByCurrency)
	if err != nil {
		return fmt.Errorf("failed to marshal prices_by_currency: %w", err)
	}

	query := `INSERT INTO token_prices (id, org_id, token_address, symbol, decimals, price_fiat, coingecko_id, updated_by_user_id, prices_by_currency)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          ON CONFLICT (org_id, token_address) DO UPDATE SET
	          symbol = EXCLUDED.symbol,
	          decimals = EXCLUDED.decimals,
	          coingecko_id = EXCLUDED.coingecko_id,
	          updated_by_user_id = EXCLUDED.updated_by_user_id,
	          prices_by_currency = token_prices.prices_by_currency || EXCLUDED.prices_by_currency,
	          price_fiat = COALESCE(
	            ((token_prices.prices_by_currency || EXCLUDED.prices_by_currency) ->> $10)::numeric,
	            EXCLUDED.price_fiat
	          ),
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		price.ID, price.OrgID, strings.ToLower(price.TokenAddress),
		price.Symbol, price.Decimals, price.PriceFiat,
		sql.NullString{String: ptrToString(price.CoingeckoID), Valid: price.CoingeckoID != nil},
		price.UpdatedByUserID, pricesByCurrency, activeCurrency,
	).Scan(&price.CreatedAt, &price.UpdatedAt)
}

func (d *DB) DeleteTokenPrice(ctx context.Context, orgID, tokenAddress string) error {
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM token_prices WHERE org_id = $1 AND token_address = $2`,
		orgID, strings.ToLower(tokenAddress))
	return err
}

func (d *DB) ListTokenPrices(ctx context.Context, orgID string) ([]*compliance.TokenPrice, error) {
	query := `SELECT id, org_id, token_address, symbol, decimals, price_fiat, coingecko_id, updated_by_user_id, prices_by_currency, created_at, updated_at
	          FROM token_prices WHERE org_id = $1 ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list token prices: %w", err)
	}
	defer rows.Close()

	return scanTokenPrices(rows)
}

func (d *DB) ListAllManualTokenPrices(ctx context.Context) ([]*compliance.TokenPrice, error) {
	query := `SELECT id, org_id, token_address, symbol, decimals, price_fiat, coingecko_id, updated_by_user_id, prices_by_currency, created_at, updated_at
	          FROM token_prices WHERE coingecko_id IS NULL ORDER BY org_id, created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list manual token prices: %w", err)
	}
	defer rows.Close()

	return scanTokenPrices(rows)
}

// Travel Rule Record operations

func (d *DB) CreateTravelRuleRecord(ctx context.Context, record *compliance.TravelRuleRecord) error {
	originatorData, err := json.Marshal(record.OriginatorData)
	if err != nil {
		return fmt.Errorf("failed to marshal originator data: %w", err)
	}

	beneficiaryData, err := json.Marshal(record.BeneficiaryData)
	if err != nil {
		return fmt.Errorf("failed to marshal beneficiary data: %w", err)
	}

	query := `INSERT INTO travel_rule_records (id, org_id, originator_user_id, originator_data, beneficiary_data,
	          transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat, currency, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	          RETURNING created_at`

	return d.conn.QueryRowContext(ctx, query,
		record.ID, record.OrgID, record.OriginatorUserID,
		originatorData, beneficiaryData,
		record.TransferType, record.TokenAddress,
		strings.ToLower(record.BeneficiaryAddress),
		record.AmountWei, record.AmountFiat, record.Currency, record.ExpiresAt,
	).Scan(&record.CreatedAt)
}

func (d *DB) GetTravelRuleRecord(ctx context.Context, id string) (*compliance.TravelRuleRecord, error) {
	query := `SELECT id, org_id, originator_user_id, originator_data, beneficiary_data,
	          transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat,
	          currency, expires_at, used_at, used_tx_hash, created_at
	          FROM travel_rule_records WHERE id = $1`

	return scanTravelRuleRecord(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) FindUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*compliance.TravelRuleRecord, error) {
	// Use COALESCE to handle NULL token_address (native ETH) matching "native" string.
	// Only match records where amount_fiat >= the transfer amount (record must cover the transfer value).
	query := `SELECT id, org_id, originator_user_id, originator_data, beneficiary_data,
	          transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat,
	          currency, expires_at, used_at, used_tx_hash, created_at
	          FROM travel_rule_records
	          WHERE org_id = $1 AND originator_user_id = $2
	          AND beneficiary_address = $3 AND COALESCE(token_address, 'native') = $4
	          AND amount_fiat >= $5
	          AND used_at IS NULL AND expires_at > NOW()
	          ORDER BY created_at DESC
	          LIMIT 1`

	return scanTravelRuleRecord(d.conn.QueryRowContext(ctx, query,
		orgID, userID, strings.ToLower(beneficiaryAddr), strings.ToLower(tokenAddr), amountFiat))
}

func (d *DB) ClaimUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*compliance.TravelRuleRecord, error) {
	// Atomically find and claim (mark as used) in a single UPDATE ... RETURNING.
	// This prevents TOCTOU race conditions: only one concurrent caller can claim a given record.
	// Only match records where amount_fiat >= the transfer amount (record must cover the transfer value).
	query := `UPDATE travel_rule_records
	          SET used_at = NOW()
	          WHERE id = (
	              SELECT id FROM travel_rule_records
	              WHERE org_id = $1 AND originator_user_id = $2
	              AND beneficiary_address = $3 AND COALESCE(token_address, 'native') = $4
	              AND amount_fiat >= $5
	              AND used_at IS NULL AND expires_at > NOW()
	              ORDER BY created_at DESC
	              LIMIT 1
	              FOR UPDATE SKIP LOCKED
	          )
	          RETURNING id, org_id, originator_user_id, originator_data, beneficiary_data,
	          transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat,
	          currency, expires_at, used_at, used_tx_hash, created_at`

	return scanTravelRuleRecord(d.conn.QueryRowContext(ctx, query,
		orgID, userID, strings.ToLower(beneficiaryAddr), strings.ToLower(tokenAddr), amountFiat))
}

func (d *DB) MarkTravelRuleRecordUsed(ctx context.Context, id string, txHash *string) error {
	query := `UPDATE travel_rule_records SET used_at = NOW(), used_tx_hash = $2
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query, id, txHash)
	return err
}

func (d *DB) ListTravelRuleRecords(ctx context.Context, orgID string, limit, offset int) ([]*compliance.TravelRuleRecord, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM travel_rule_records WHERE org_id = $1`
	if err := d.conn.QueryRowContext(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count travel rule records: %w", err)
	}

	// Get paginated results with user external_id
	query := `SELECT tr.id, tr.org_id, tr.originator_user_id, COALESCE(u.external_id, ''), tr.originator_data, tr.beneficiary_data,
	          tr.transfer_type, tr.token_address, tr.beneficiary_address, tr.amount_wei, tr.amount_fiat,
	          tr.currency, tr.expires_at, tr.used_at, tr.used_tx_hash, tr.created_at
	          FROM travel_rule_records tr LEFT JOIN users u ON u.id = tr.originator_user_id
	          WHERE tr.org_id = $1
	          ORDER BY tr.created_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list travel rule records: %w", err)
	}
	defer rows.Close()

	records, err := scanTravelRuleRecords(rows)
	if err != nil {
		return nil, 0, err
	}

	return records, total, nil
}

func (d *DB) DeleteTravelRuleRecord(ctx context.Context, orgID, id string) error {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM travel_rule_records WHERE id = $1 AND org_id = $2 AND used_at IS NULL`,
		id, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete travel rule record: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		// Distinguish "not found" from "already used" by checking if the record exists at all.
		var exists bool
		err := d.conn.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM travel_rule_records WHERE id = $1 AND org_id = $2)`,
			id, orgID).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check travel rule record existence: %w", err)
		}
		if exists {
			return ErrRecordAlreadyUsed
		}
		return ErrNotFound
	}

	return nil
}

func (d *DB) CleanupExpiredRecords(ctx context.Context) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM travel_rule_records WHERE expires_at < NOW() AND used_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired records: %w", err)
	}
	return result.RowsAffected()
}

// Address Threshold Override operations

func (d *DB) GetAddressThresholdOverride(ctx context.Context, orgID, address string) (*compliance.AddressThresholdOverride, error) {
	query := `SELECT id, org_id, address, threshold_fiat, note, created_at, updated_at
	          FROM address_threshold_overrides WHERE org_id = $1 AND address = $2`

	override := &compliance.AddressThresholdOverride{}
	var note sql.NullString
	err := d.conn.QueryRowContext(ctx, query, orgID, strings.ToLower(address)).Scan(
		&override.ID, &override.OrgID, &override.Address, &override.ThresholdFiat,
		&note, &override.CreatedAt, &override.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get address threshold override: %w", err)
	}
	if note.Valid {
		override.Note = note.String
	}
	return override, nil
}

func (d *DB) ListAddressThresholdOverrides(ctx context.Context, orgID string, limit, offset int) ([]*compliance.AddressThresholdOverride, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM address_threshold_overrides WHERE org_id = $1`, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count address threshold overrides: %w", err)
	}

	query := `SELECT id, org_id, address, threshold_fiat, note, created_at, updated_at
	          FROM address_threshold_overrides WHERE org_id = $1
	          ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list address threshold overrides: %w", err)
	}
	defer rows.Close()

	var overrides []*compliance.AddressThresholdOverride
	for rows.Next() {
		o := &compliance.AddressThresholdOverride{}
		var note sql.NullString
		if err := rows.Scan(&o.ID, &o.OrgID, &o.Address, &o.ThresholdFiat,
			&note, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan address threshold override: %w", err)
		}
		if note.Valid {
			o.Note = note.String
		}
		overrides = append(overrides, o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating address threshold overrides: %w", err)
	}

	return overrides, total, nil
}

func (d *DB) UpsertAddressThresholdOverride(ctx context.Context, override *compliance.AddressThresholdOverride) error {
	query := `INSERT INTO address_threshold_overrides (id, org_id, address, threshold_fiat, note)
	          VALUES ($1, $2, $3, $4, $5)
	          ON CONFLICT (org_id, address) DO UPDATE SET
	          threshold_fiat = EXCLUDED.threshold_fiat,
	          note = EXCLUDED.note,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		override.ID, override.OrgID, strings.ToLower(override.Address),
		override.ThresholdFiat, sql.NullString{String: override.Note, Valid: override.Note != ""},
	).Scan(&override.CreatedAt, &override.UpdatedAt)
}

func (d *DB) DeleteAddressThresholdOverride(ctx context.Context, orgID, address string) error {
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM address_threshold_overrides WHERE org_id = $1 AND address = $2`,
		orgID, strings.ToLower(address))
	return err
}

// Sanctioned Address operations

func (d *DB) IsAddressSanctioned(ctx context.Context, orgID, address string) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM sanctioned_addresses
		WHERE address = $1 AND (org_id IS NULL OR org_id = $2)
	)`

	var exists bool
	err := d.conn.QueryRowContext(ctx, query, strings.ToLower(address), orgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check sanctioned address: %w", err)
	}
	return exists, nil
}

func (d *DB) AddSanctionedAddress(ctx context.Context, sanction *compliance.SanctionedAddress) error {
	query := `INSERT INTO sanctioned_addresses (id, org_id, address, reason, source, added_by_user_id)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		sanction.ID, sanction.OrgID, strings.ToLower(sanction.Address),
		sanction.Reason, sanction.Source, sanction.AddedByUserID,
	).Scan(&sanction.CreatedAt, &sanction.UpdatedAt)
}

func (d *DB) RemoveSanctionedAddress(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM sanctioned_addresses WHERE id = $1`, id)
	return err
}

func (d *DB) GetSanctionedAddress(ctx context.Context, id string) (*compliance.SanctionedAddress, error) {
	query := `SELECT id, org_id, address, reason, source, added_by_user_id, created_at, updated_at
	          FROM sanctioned_addresses WHERE id = $1`

	return scanSanctionedAddress(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) ListSanctionedAddresses(ctx context.Context, orgID *string, limit, offset int) ([]*compliance.SanctionedAddress, int, error) {
	var total int
	var countQuery string
	var countArgs []any

	if orgID != nil {
		countQuery = `SELECT COUNT(*) FROM sanctioned_addresses WHERE org_id = $1`
		countArgs = []any{*orgID}
	} else {
		countQuery = `SELECT COUNT(*) FROM sanctioned_addresses WHERE org_id IS NULL`
	}

	if err := d.conn.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count sanctioned addresses: %w", err)
	}

	var query string
	var args []any

	if orgID != nil {
		query = `SELECT id, org_id, address, reason, source, added_by_user_id, created_at, updated_at
		         FROM sanctioned_addresses WHERE org_id = $1
		         ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{*orgID, limit, offset}
	} else {
		query = `SELECT id, org_id, address, reason, source, added_by_user_id, created_at, updated_at
		         FROM sanctioned_addresses WHERE org_id IS NULL
		         ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		args = []any{limit, offset}
	}

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sanctioned addresses: %w", err)
	}
	defer rows.Close()

	sanctions, err := scanSanctionedAddresses(rows)
	if err != nil {
		return nil, 0, err
	}

	return sanctions, total, nil
}

// Compliance Log operations

func (d *DB) CreateComplianceLog(ctx context.Context, entry *compliance.ComplianceLog) (int64, error) {
	query := `INSERT INTO compliance_logs (org_id, user_id, transfer_type, token_address,
	          from_address, to_address, amount_wei, amount_fiat, threshold_fiat,
	          currency, decision, denial_reason, would_block, travel_rule_record_id, correlation_id)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	          RETURNING id, created_at`

	var corrID *string
	if entry.CorrelationID != "" {
		corrID = &entry.CorrelationID
	}

	err := d.conn.QueryRowContext(ctx, query,
		entry.OrgID, entry.UserID, entry.TransferType, entry.TokenAddress,
		strings.ToLower(entry.FromAddress), strings.ToLower(entry.ToAddress),
		entry.AmountWei, entry.AmountFiat, entry.ThresholdFiat,
		entry.Currency, entry.Decision, entry.DenialReason, entry.WouldBlock, entry.TravelRuleRecordID,
		corrID,
	).Scan(&entry.ID, &entry.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("failed to create compliance log: %w", err)
	}

	return entry.ID, nil
}

func (d *DB) GetComplianceLog(ctx context.Context, id int64) (*compliance.ComplianceLog, error) {
	query := `SELECT id, org_id, user_id, transfer_type, token_address,
	          from_address, to_address, amount_wei, amount_fiat, threshold_fiat,
	          currency, decision, denial_reason, would_block, travel_rule_record_id, created_at
	          FROM compliance_logs WHERE id = $1`

	return scanComplianceLog(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) ListComplianceLogs(ctx context.Context, orgID string, filters *compliance.ComplianceLogFilters) ([]*compliance.ComplianceLog, int, error) {
	// Build WHERE clause
	where := `WHERE cl.org_id = $1`
	args := []any{orgID}
	paramIdx := 2

	if filters != nil {
		if filters.UserSearch != nil {
			where += fmt.Sprintf(` AND u.external_id ILIKE '%%' || $%d || '%%'`, paramIdx)
			args = append(args, *filters.UserSearch)
			paramIdx++
		}
		if filters.Decision != nil {
			where += fmt.Sprintf(` AND cl.decision = $%d`, paramIdx)
			args = append(args, *filters.Decision)
			paramIdx++
		}
		if filters.TransferType != nil {
			where += fmt.Sprintf(` AND cl.transfer_type = $%d`, paramIdx)
			args = append(args, *filters.TransferType)
			paramIdx++
		}
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM compliance_logs cl LEFT JOIN users u ON u.id = cl.user_id ` + where
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count compliance logs: %w", err)
	}

	// Get paginated results
	limit := 50
	offset := 0
	if filters != nil {
		if filters.Limit > 0 {
			limit = filters.Limit
		}
		if filters.Offset > 0 {
			offset = filters.Offset
		}
	}

	query := fmt.Sprintf(`SELECT cl.id, cl.org_id, cl.user_id, COALESCE(u.external_id, ''), cl.transfer_type, cl.token_address,
	          cl.from_address, cl.to_address, cl.amount_wei, cl.amount_fiat, cl.threshold_fiat,
	          cl.currency, cl.decision, cl.denial_reason, cl.would_block, cl.travel_rule_record_id, cl.created_at
	          FROM compliance_logs cl LEFT JOIN users u ON u.id = cl.user_id
	          %s ORDER BY cl.created_at DESC LIMIT $%d OFFSET $%d`,
		where, paramIdx, paramIdx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list compliance logs: %w", err)
	}
	defer rows.Close()

	logs, err := scanComplianceLogs(rows)
	if err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// Scan helpers

func scanTokenPrice(row *sql.Row) (*compliance.TokenPrice, error) {
	price := &compliance.TokenPrice{}
	var updatedByUserID, coingeckoID sql.NullString
	var pricesByCurrencyJSON []byte

	err := row.Scan(
		&price.ID, &price.OrgID, &price.TokenAddress, &price.Symbol,
		&price.Decimals, &price.PriceFiat, &coingeckoID, &updatedByUserID,
		&pricesByCurrencyJSON, &price.CreatedAt, &price.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan token price: %w", err)
	}

	if coingeckoID.Valid {
		price.CoingeckoID = &coingeckoID.String
	}
	if updatedByUserID.Valid {
		price.UpdatedByUserID = &updatedByUserID.String
	}
	if len(pricesByCurrencyJSON) > 0 {
		if err := json.Unmarshal(pricesByCurrencyJSON, &price.PricesByCurrency); err != nil {
			slog.Warn("corrupt prices_by_currency JSON for token", "token_address", price.TokenAddress, "error", err)
		}
	}

	return price, nil
}

func scanTokenPrices(rows *sql.Rows) ([]*compliance.TokenPrice, error) {
	var prices []*compliance.TokenPrice
	for rows.Next() {
		price := &compliance.TokenPrice{}
		var updatedByUserID, coingeckoID sql.NullString
		var pricesByCurrencyJSON []byte

		if err := rows.Scan(
			&price.ID, &price.OrgID, &price.TokenAddress, &price.Symbol,
			&price.Decimals, &price.PriceFiat, &coingeckoID, &updatedByUserID,
			&pricesByCurrencyJSON, &price.CreatedAt, &price.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan token price: %w", err)
		}

		if coingeckoID.Valid {
			price.CoingeckoID = &coingeckoID.String
		}
		if updatedByUserID.Valid {
			price.UpdatedByUserID = &updatedByUserID.String
		}
		if len(pricesByCurrencyJSON) > 0 {
			if err := json.Unmarshal(pricesByCurrencyJSON, &price.PricesByCurrency); err != nil {
			slog.Warn("corrupt prices_by_currency JSON for token", "token_address", price.TokenAddress, "error", err)
		}
		}

		prices = append(prices, price)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating token prices: %w", err)
	}

	return prices, nil
}

// ptrToString safely dereferences a *string, returning "" for nil.
func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func scanTravelRuleRecord(row *sql.Row) (*compliance.TravelRuleRecord, error) {
	record := &compliance.TravelRuleRecord{}
	var originatorData, beneficiaryData []byte
	var tokenAddress sql.NullString
	var usedAt sql.NullTime
	var usedTxHash sql.NullString

	err := row.Scan(
		&record.ID, &record.OrgID, &record.OriginatorUserID,
		&originatorData, &beneficiaryData,
		&record.TransferType, &tokenAddress, &record.BeneficiaryAddress,
		&record.AmountWei, &record.AmountFiat,
		&record.Currency, &record.ExpiresAt, &usedAt, &usedTxHash, &record.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan travel rule record: %w", err)
	}

	if len(originatorData) > 0 {
		if err := json.Unmarshal(originatorData, &record.OriginatorData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal originator data: %w", err)
		}
	}
	if len(beneficiaryData) > 0 {
		if err := json.Unmarshal(beneficiaryData, &record.BeneficiaryData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal beneficiary data: %w", err)
		}
	}
	if tokenAddress.Valid {
		record.TokenAddress = &tokenAddress.String
	}
	if usedAt.Valid {
		record.UsedAt = &usedAt.Time
	}
	if usedTxHash.Valid {
		record.UsedTxHash = &usedTxHash.String
	}

	return record, nil
}

func scanTravelRuleRecords(rows *sql.Rows) ([]*compliance.TravelRuleRecord, error) {
	var records []*compliance.TravelRuleRecord
	for rows.Next() {
		record := &compliance.TravelRuleRecord{}
		var originatorData, beneficiaryData []byte
		var tokenAddress sql.NullString
		var usedAt sql.NullTime
		var usedTxHash sql.NullString

		if err := rows.Scan(
			&record.ID, &record.OrgID, &record.OriginatorUserID,
			&record.OriginatorExternalID,
			&originatorData, &beneficiaryData,
			&record.TransferType, &tokenAddress, &record.BeneficiaryAddress,
			&record.AmountWei, &record.AmountFiat,
			&record.Currency, &record.ExpiresAt, &usedAt, &usedTxHash, &record.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan travel rule record: %w", err)
		}

		if len(originatorData) > 0 {
			if err := json.Unmarshal(originatorData, &record.OriginatorData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal originator data: %w", err)
			}
		}
		if len(beneficiaryData) > 0 {
			if err := json.Unmarshal(beneficiaryData, &record.BeneficiaryData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal beneficiary data: %w", err)
			}
		}
		if tokenAddress.Valid {
			record.TokenAddress = &tokenAddress.String
		}
		if usedAt.Valid {
			record.UsedAt = &usedAt.Time
		}
		if usedTxHash.Valid {
			record.UsedTxHash = &usedTxHash.String
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating travel rule records: %w", err)
	}

	return records, nil
}

func scanSanctionedAddress(row *sql.Row) (*compliance.SanctionedAddress, error) {
	sanction := &compliance.SanctionedAddress{}
	var orgID, source, addedByUserID sql.NullString

	err := row.Scan(
		&sanction.ID, &orgID, &sanction.Address, &sanction.Reason,
		&source, &addedByUserID,
		&sanction.CreatedAt, &sanction.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan sanctioned address: %w", err)
	}

	if orgID.Valid {
		sanction.OrgID = &orgID.String
	}
	if source.Valid {
		sanction.Source = source.String
	}
	if addedByUserID.Valid {
		sanction.AddedByUserID = &addedByUserID.String
	}

	return sanction, nil
}

func scanSanctionedAddresses(rows *sql.Rows) ([]*compliance.SanctionedAddress, error) {
	var sanctions []*compliance.SanctionedAddress
	for rows.Next() {
		sanction := &compliance.SanctionedAddress{}
		var orgID, source, addedByUserID sql.NullString

		if err := rows.Scan(
			&sanction.ID, &orgID, &sanction.Address, &sanction.Reason,
			&source, &addedByUserID,
			&sanction.CreatedAt, &sanction.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan sanctioned address: %w", err)
		}

		if orgID.Valid {
			sanction.OrgID = &orgID.String
		}
		if source.Valid {
			sanction.Source = source.String
		}
		if addedByUserID.Valid {
			sanction.AddedByUserID = &addedByUserID.String
		}

		sanctions = append(sanctions, sanction)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sanctioned addresses: %w", err)
	}

	return sanctions, nil
}

func scanComplianceLog(row *sql.Row) (*compliance.ComplianceLog, error) {
	entry := &compliance.ComplianceLog{}
	var tokenAddress, denialReason, travelRuleRecordID sql.NullString
	var amountFiat, thresholdFiat sql.NullFloat64

	err := row.Scan(
		&entry.ID, &entry.OrgID, &entry.UserID, &entry.TransferType, &tokenAddress,
		&entry.FromAddress, &entry.ToAddress, &entry.AmountWei,
		&amountFiat, &thresholdFiat,
		&entry.Currency, &entry.Decision, &denialReason, &entry.WouldBlock, &travelRuleRecordID, &entry.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan compliance log: %w", err)
	}

	if tokenAddress.Valid {
		entry.TokenAddress = &tokenAddress.String
	}
	if amountFiat.Valid {
		entry.AmountFiat = &amountFiat.Float64
	}
	if thresholdFiat.Valid {
		entry.ThresholdFiat = &thresholdFiat.Float64
	}
	if denialReason.Valid {
		entry.DenialReason = &denialReason.String
	}
	if travelRuleRecordID.Valid {
		entry.TravelRuleRecordID = &travelRuleRecordID.String
	}

	return entry, nil
}

// System Settings operations

func (d *DB) GetSystemSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := d.conn.QueryRowContext(ctx,
		`SELECT value FROM system_settings WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get system setting %s: %w", key, err)
	}
	return value, nil
}

func (d *DB) SetSystemSetting(ctx context.Context, key, value string) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`,
		key, value)
	return err
}


// stringSlice is a helper for scanning PostgreSQL text[] into []string via pgx.
type stringSlice []string

func (s *stringSlice) Scan(src interface{}) error {
	if src == nil {
		*s = nil
		return nil
	}
	switch v := src.(type) {
	case []byte:
		return scanPGTextArray(v, s)
	case string:
		return scanPGTextArray([]byte(v), s)
	default:
		return fmt.Errorf("unsupported type for stringSlice: %T", src)
	}
}

func scanPGTextArray(data []byte, result *stringSlice) error {
	str := string(data)
	if str == "{}" || str == "" {
		*result = nil
		return nil
	}
	// Strip surrounding braces
	if len(str) >= 2 && str[0] == '{' && str[len(str)-1] == '}' {
		str = str[1 : len(str)-1]
	}
	parts := strings.Split(str, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		// Strip quotes if present
		p = strings.TrimSpace(p)
		if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
			p = p[1 : len(p)-1]
		}
		out = append(out, p)
	}
	*result = out
	return nil
}

func scanComplianceLogs(rows *sql.Rows) ([]*compliance.ComplianceLog, error) {
	var logs []*compliance.ComplianceLog
	for rows.Next() {
		entry := &compliance.ComplianceLog{}
		var tokenAddress, denialReason, travelRuleRecordID sql.NullString
		var amountFiat, thresholdFiat sql.NullFloat64

		if err := rows.Scan(
			&entry.ID, &entry.OrgID, &entry.UserID, &entry.UserExternalID, &entry.TransferType, &tokenAddress,
			&entry.FromAddress, &entry.ToAddress, &entry.AmountWei,
			&amountFiat, &thresholdFiat,
			&entry.Currency, &entry.Decision, &denialReason, &entry.WouldBlock, &travelRuleRecordID, &entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan compliance log: %w", err)
		}

		if tokenAddress.Valid {
			entry.TokenAddress = &tokenAddress.String
		}
		if amountFiat.Valid {
			entry.AmountFiat = &amountFiat.Float64
		}
		if thresholdFiat.Valid {
			entry.ThresholdFiat = &thresholdFiat.Float64
		}
		if denialReason.Valid {
			entry.DenialReason = &denialReason.String
		}
		if travelRuleRecordID.Valid {
			entry.TravelRuleRecordID = &travelRuleRecordID.String
		}

		logs = append(logs, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating compliance logs: %w", err)
	}

	return logs, nil
}
