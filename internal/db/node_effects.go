package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

// ErrBelowReplayFloor: the transaction's finalized block is at or below the
// network's replay floor, so its effects may no longer be applied (G57).
var ErrBelowReplayFloor = errors.New("node transaction effects are below the replay floor")

// ErrReplayFloorMissing: the network has no replay floor row; effects are
// refused until OPS initialises it (fail closed).
var ErrReplayFloorMissing = errors.New("node transaction effects replay floor is not initialised")

// NodeTxEffects are the main-database side effects of one finalized
// transaction (plan §4.11): ownership of the contracts it created and the
// visibility rule of its visibleTo. Only the requested effects are applied.
type NodeTxEffects struct {
	TransactionHash string // 0x-prefixed lowercase hex
	PrincipalID     string
	OrgID           string
	BlockNumber     uint64
	// Ownership requests registration of Created (an included transaction).
	Ownership bool
	Created   []nodepolicy.CreatedContract
	// Visibility requests the visibleTo rule for VisibleTo, sent by
	// VisibleSender.
	Visibility    bool
	VisibleTo     []string
	VisibleSender string
}

// NodeTxEffectsResult reports what the call did; Note is
// "organization_deleted" when the organization is gone (nothing applied).
// OwnershipConflicts counts created addresses another organisation already
// owns: they are never registered (the others are).
type NodeTxEffectsResult struct {
	OwnershipApplied, VisibilityApplied bool
	OwnershipConflicts                  int
	Note                                string
}

// EnsureNodeTxEffectsFloor creates the network's replay floor at 0 if absent.
// It is the "chain registration" of the floor: OPS calls it at startup for
// its configured network; an existing floor is never lowered or replaced.
func (d *DB) EnsureNodeTxEffectsFloor(ctx context.Context, network nodepolicy.Network) error {
	if network.ChainID == 0 || network.ChainID > 1<<63-1 || network.DeploymentID == "" {
		return fmt.Errorf("invalid node effects network")
	}
	_, err := d.conn.ExecContext(ctx, `INSERT INTO node_tx_effects_floor (chain_id, deployment_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, int64(network.ChainID), network.DeploymentID)
	return err
}

// NodeTxEffectsFloor reads the replay floor (ErrReplayFloorMissing if absent).
func (d *DB) NodeTxEffectsFloor(ctx context.Context, network nodepolicy.Network) (uint64, error) {
	var floor int64
	err := d.conn.QueryRowContext(ctx, `SELECT floor_block FROM node_tx_effects_floor WHERE chain_id = $1 AND deployment_id = $2`, int64(network.ChainID), network.DeploymentID).Scan(&floor)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrReplayFloorMissing
	}
	return uint64(floor), err
}

func txHashBytes(hash string) ([]byte, error) {
	if !validSubmissionHex(hash, 32) {
		return nil, fmt.Errorf("invalid transaction hash")
	}
	return hex.DecodeString(hash[2:])
}

// ApplyNodeTxEffects applies the requested effects of one finalized
// transaction exactly once in effect (G48, G57, G67), in one main-database
// transaction:
//
//  1. the network's replay floor is read FOR SHARE and held to commit: an
//     absent floor, or a block at or below it, refuses (cleanup takes the
//     same row FOR UPDATE before raising it or pruning markers, so a
//     finalizer paused after its read either finishes first or sees the new
//     floor);
//  2. the marker is inserted if absent and locked (insert-or-find, then lock);
//  3. only requested effects whose bit is not yet set are applied, and their
//     bits are set in the same transaction. A set bit is never re-applied, so
//     a later revocation by an administrator stands.
//
// Lock order: floor, marker, then the organization's configuration scope.
func (d *DB) ApplyNodeTxEffects(ctx context.Context, network nodepolicy.Network, effects NodeTxEffects) (NodeTxEffectsResult, error) {
	var result NodeTxEffectsResult
	hash, err := txHashBytes(effects.TransactionHash)
	if err != nil {
		return result, err
	}
	if !effects.Ownership && !effects.Visibility {
		return result, nil
	}
	if effects.BlockNumber > 1<<63-1 {
		return result, fmt.Errorf("invalid block number")
	}
	if effects.Visibility && (len(effects.VisibleTo) == 0 || effects.VisibleSender == "") {
		return result, fmt.Errorf("visibility effect without recipients or sender")
	}
	err = withRetry(ctx, func() error {
		result = NodeTxEffectsResult{}
		return d.WithTx(ctx, func(tx *Tx) error {
			var floor int64
			err := tx.tx.QueryRowContext(ctx, `SELECT floor_block FROM node_tx_effects_floor WHERE chain_id = $1 AND deployment_id = $2 FOR SHARE`, int64(network.ChainID), network.DeploymentID).Scan(&floor)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrReplayFloorMissing
			}
			if err != nil {
				return err
			}
			if int64(effects.BlockNumber) <= floor {
				return ErrBelowReplayFloor
			}
			if _, err := tx.tx.ExecContext(ctx, `INSERT INTO node_tx_effects_applied (chain_id, deployment_id, tx_hash, block_number) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, int64(network.ChainID), network.DeploymentID, hash, int64(effects.BlockNumber)); err != nil {
				return err
			}
			var ownershipDone, visibilityDone bool
			if err := tx.tx.QueryRowContext(ctx, `SELECT ownership, visibility FROM node_tx_effects_applied WHERE chain_id = $1 AND deployment_id = $2 AND tx_hash = $3 FOR UPDATE`, int64(network.ChainID), network.DeploymentID, hash).Scan(&ownershipDone, &visibilityDone); err != nil {
				return err
			}
			wantOwnership := effects.Ownership && !ownershipDone && len(effects.Created) > 0
			wantVisibility := effects.Visibility && !visibilityDone
			if !wantOwnership && !wantVisibility {
				return nil
			}
			// Only registration writes configuration state, so only it takes
			// the organisation's configuration scope; visibility needs the
			// organisation to exist (FOR KEY SHARE conflicts with deletion).
			var orgErr error
			if wantOwnership {
				orgErr = tx.AuthorizeDeploymentRegistration(ctx, effects.OrgID)
			} else {
				var id string
				orgErr = tx.tx.QueryRowContext(ctx, `SELECT id FROM organizations WHERE id = $1 FOR KEY SHARE`, effects.OrgID).Scan(&id)
			}
			if errors.Is(orgErr, sql.ErrNoRows) {
				result.Note = "organization_deleted"
				return nil
			}
			if orgErr != nil {
				return orgErr
			}
			if wantOwnership {
				for _, created := range effects.Created {
					err := reconcileNodeContract(ctx, tx, nodeContractOrigin{TransactionHash: effects.TransactionHash, PrincipalID: effects.PrincipalID, OrgID: effects.OrgID}, created)
					if errors.Is(err, ErrNodeSubmissionConflict) {
						// Owned by another organisation (checked before any
						// write): never re-registered; the others still are.
						result.OwnershipConflicts++
						continue
					}
					if err != nil {
						return err
					}
				}
				result.OwnershipApplied = true
			}
			if wantVisibility {
				if _, err := tx.tx.ExecContext(ctx, `INSERT INTO pending_tx_visibility (tx_hash, visible_to_dids, sender_did, org_id) VALUES ($1, $2, $3, $4)`, effects.TransactionHash, effects.VisibleTo, effects.VisibleSender, effects.OrgID); err != nil {
					return err
				}
				result.VisibilityApplied = true
			}
			_, err = tx.tx.ExecContext(ctx, `UPDATE node_tx_effects_applied SET ownership = ownership OR $4, visibility = visibility OR $5 WHERE chain_id = $1 AND deployment_id = $2 AND tx_hash = $3`, int64(network.ChainID), network.DeploymentID, hash, result.OwnershipApplied, result.VisibilityApplied)
			return err
		})
	})
	return result, err
}

// PruneNodeTxEffects deletes the markers applied before olderThan and raises
// the replay floor to the highest block they covered (never lowering it), in
// one transaction that takes the floor FOR UPDATE first (G57).
func (d *DB) PruneNodeTxEffects(ctx context.Context, network nodepolicy.Network, olderThan time.Time) (int64, error) {
	var deleted int64
	err := withRetry(ctx, func() error {
		return d.WithTx(ctx, func(tx *Tx) error {
			var floor int64
			err := tx.tx.QueryRowContext(ctx, `SELECT floor_block FROM node_tx_effects_floor WHERE chain_id = $1 AND deployment_id = $2 FOR UPDATE`, int64(network.ChainID), network.DeploymentID).Scan(&floor)
			if errors.Is(err, sql.ErrNoRows) {
				deleted = 0
				return nil
			}
			if err != nil {
				return err
			}
			var highest sql.NullInt64
			if err := tx.tx.QueryRowContext(ctx, `WITH gone AS (DELETE FROM node_tx_effects_applied WHERE chain_id = $1 AND deployment_id = $2 AND applied_at < $3 RETURNING block_number)
 SELECT count(*), max(block_number) FROM gone`, int64(network.ChainID), network.DeploymentID, olderThan).Scan(&deleted, &highest); err != nil {
				return err
			}
			if highest.Valid && highest.Int64 > floor {
				_, err = tx.tx.ExecContext(ctx, `UPDATE node_tx_effects_floor SET floor_block = $3, updated_at = clock_timestamp() WHERE chain_id = $1 AND deployment_id = $2`, int64(network.ChainID), network.DeploymentID, highest.Int64)
			}
			return err
		})
	})
	return deleted, err
}

// nodeContractOrigin is the binding of a finalized deployment.
type nodeContractOrigin struct {
	TransactionHash, PrincipalID, OrgID string
}

func reconcileNodeContract(ctx context.Context, tx *Tx, submission nodeContractOrigin, created nodepolicy.CreatedContract) error {
	var id, owner string
	err := tx.tx.QueryRowContext(ctx, `SELECT id,org_id FROM contracts WHERE lower(address)=$1 FOR UPDATE`, created.Address).Scan(&id, &owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && owner != submission.OrgID {
		return ErrNodeSubmissionConflict
	}
	var existingPrincipal string
	principalErr := tx.tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 FOR KEY SHARE`, submission.PrincipalID).Scan(&existingPrincipal)
	if principalErr != nil && !errors.Is(principalErr, sql.ErrNoRows) {
		return principalErr
	}
	var deployer *string
	if principalErr == nil {
		deployer = &existingPrincipal
	}
	metadata := map[string]any{"auto_registered": true, "via": "node_execution", "transaction": submission.TransactionHash, "deployer_principal": submission.PrincipalID}
	if errors.Is(err, sql.ErrNoRows) {
		now := time.Now()
		id = uuid.NewString()
		contract := &rbac.Contract{ID: id, OrgID: submission.OrgID, Address: created.Address, Name: "Contract " + created.Address[:10], DeployedByUserID: deployer, DeployedAt: &now, Metadata: metadata}
		if err := tx.CreateContract(ctx, contract); err != nil {
			return err
		}
	} else {
		// A pre-registered catalog entry keeps its reviewed ABI/name, while
		// actual chain evidence supplies the deployer used by access rules.
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE contracts SET deployed_by_user_id=$2,deployed_at=clock_timestamp(),metadata=(CASE WHEN jsonb_typeof(metadata)='object' THEN metadata ELSE '{}'::jsonb END)||$3::jsonb,updated_at=clock_timestamp() WHERE id=$1`, id, deployer, encoded); err != nil {
			return err
		}
	}
	// Preserve the existing deploy-group auto-grant semantics using only a
	// current, active deployment group. Revoked memberships add no grant.
	_, err = tx.tx.ExecContext(ctx, `INSERT INTO contract_grants(id,contract_id,group_id)
 SELECT $1,$2,g.id FROM user_memberships m JOIN groups g ON g.id=m.group_id JOIN group_access ga ON ga.group_id=g.id JOIN users u ON u.id=m.user_id
 WHERE m.user_id=$3 AND g.org_id=$4 AND NOT u.banned AND (m.expires_at IS NULL OR m.expires_at>NOW())
 AND (g.is_org_admin OR 'deploy'=ANY(ga.claims) OR 'admin'=ANY(ga.claims)) ORDER BY g.id LIMIT 1 ON CONFLICT(contract_id,group_id) DO NOTHING`, uuid.NewString(), id, submission.PrincipalID, submission.OrgID)
	return err
}

// lowerHex is a 0x-prefixed lowercase hex string of b.
func lowerHex(b []byte) string { return "0x" + strings.ToLower(hex.EncodeToString(b)) }

// travelRuleColumns are the travel_rule_records columns scanTravelRuleRecord
// reads, in order.
const travelRuleColumns = `id, org_id, originator_user_id, originator_data, beneficiary_data,
	          transfer_type, token_address, beneficiary_address, amount_wei, amount_fiat,
	          currency, expires_at, used_at, used_tx_hash, created_at`

var errTravelRuleClaimRace = errors.New("concurrent travel-rule claim for the same transaction")

// ClaimTravelRuleRecordForTx is the one-claim-per-transaction travel-rule step
// of the Reth path (plan §4.8.5, G60). One record is bound to (network,
// transaction hash) in node_tx_compliance_claims:
//
//  1. a bound record is re-found and re-used — a same-transaction retry or
//     renewal never consumes a second record — but only while it still covers
//     this transfer (organisation, originator, beneficiary, token, amount);
//     otherwise there is no record (never another one);
//  2. without a bound record, an unused covering record is claimed (marked
//     used, with the transaction hash) and bound, in one transaction;
//  3. if a concurrent call for the same transaction bound one first, this
//     call's claim is rolled back (its record stays unused) and the winner is
//     returned under the same coverage check.
//
// A nil record means no covering record (the checker decides what that means).
func (d *DB) ClaimTravelRuleRecordForTx(ctx context.Context, chainID uint64, deploymentID, txHash, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*compliance.TravelRuleRecord, error) {
	hash, err := txHashBytes(txHash)
	if err != nil {
		return nil, err
	}
	if chainID == 0 || chainID > 1<<63-1 || deploymentID == "" {
		return nil, fmt.Errorf("invalid travel-rule transaction network")
	}
	key := []any{int64(chainID), deploymentID, hash}
	covering := func(tx *Tx) (*compliance.TravelRuleRecord, bool, error) {
		var id string
		err := tx.tx.QueryRowContext(ctx, `SELECT travel_rule_record_id FROM node_tx_compliance_claims WHERE chain_id = $1 AND deployment_id = $2 AND tx_hash = $3`, key...).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		record, err := scanTravelRuleRecord(tx.tx.QueryRowContext(ctx, `SELECT `+travelRuleColumns+` FROM travel_rule_records
 WHERE id = $1 AND org_id = $2 AND originator_user_id = $3 AND beneficiary_address = $4 AND COALESCE(token_address, 'native') = $5 AND amount_fiat >= $6`,
			id, orgID, userID, strings.ToLower(beneficiaryAddr), strings.ToLower(tokenAddr), amountFiat))
		return record, true, err
	}
	var record *compliance.TravelRuleRecord
	err = d.WithTx(ctx, func(tx *Tx) error {
		bound, found, err := covering(tx)
		if err != nil || found {
			record = bound
			return err
		}
		claimed, err := scanTravelRuleRecord(tx.tx.QueryRowContext(ctx, `UPDATE travel_rule_records SET used_at = NOW(), used_tx_hash = $6
 WHERE id = (SELECT id FROM travel_rule_records
             WHERE org_id = $1 AND originator_user_id = $2 AND beneficiary_address = $3 AND COALESCE(token_address, 'native') = $4
               AND amount_fiat >= $5 AND used_at IS NULL AND expires_at > NOW()
             ORDER BY created_at DESC LIMIT 1 FOR UPDATE SKIP LOCKED)
 RETURNING `+travelRuleColumns, orgID, userID, strings.ToLower(beneficiaryAddr), strings.ToLower(tokenAddr), amountFiat, txHash))
		if err != nil || claimed == nil {
			return err
		}
		var winner string
		err = tx.tx.QueryRowContext(ctx, `INSERT INTO node_tx_compliance_claims (chain_id, deployment_id, tx_hash, travel_rule_record_id) VALUES ($1, $2, $3, $4) ON CONFLICT (chain_id, deployment_id, tx_hash) DO NOTHING RETURNING travel_rule_record_id`, append(key, claimed.ID)...).Scan(&winner)
		if errors.Is(err, sql.ErrNoRows) {
			return errTravelRuleClaimRace // roll back: this call's record stays unused
		}
		if err != nil {
			return err
		}
		record = claimed
		return nil
	})
	if errors.Is(err, errTravelRuleClaimRace) {
		err = d.WithTx(ctx, func(tx *Tx) error {
			var e error
			record, _, e = covering(tx)
			return e
		})
	}
	if err != nil {
		return nil, err
	}
	return record, nil
}

// BoundTravelRuleRecordForTx is the renewal mode of the travel-rule step
// (plan §4.8.5): the record bound to (network, tx_hash) if it still covers
// the transfer (org, originator, beneficiary, token, amount), else nil. It
// never claims a record; the bound record's own expiry is not re-checked
// (the binding is the authorization, K13).
func (d *DB) BoundTravelRuleRecordForTx(ctx context.Context, chainID uint64, deploymentID, txHash, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*compliance.TravelRuleRecord, error) {
	hash, err := txHashBytes(txHash)
	if err != nil {
		return nil, err
	}
	if chainID == 0 || chainID > 1<<63-1 || deploymentID == "" {
		return nil, fmt.Errorf("invalid travel-rule transaction network")
	}
	record, err := scanTravelRuleRecord(d.conn.QueryRowContext(ctx, `SELECT `+travelRuleColumns+` FROM travel_rule_records
 WHERE id = (SELECT travel_rule_record_id FROM node_tx_compliance_claims WHERE chain_id = $1 AND deployment_id = $2 AND tx_hash = $3)
   AND org_id = $4 AND originator_user_id = $5 AND beneficiary_address = $6 AND COALESCE(token_address, 'native') = $7 AND amount_fiat >= $8`,
		int64(chainID), deploymentID, hash, orgID, userID, strings.ToLower(beneficiaryAddr), strings.ToLower(tokenAddr), amountFiat))
	if err != nil {
		return nil, err
	}
	return record, nil
}

// ExternalIDsByUserID maps user ids to their external ids (DIDs); deleted
// users are absent.
func (d *DB) ExternalIDsByUserID(ctx context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT id::text, external_id FROM users WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, external string
		if err := rows.Scan(&id, &external); err != nil {
			return nil, err
		}
		out[id] = external
	}
	return out, rows.Err()
}
