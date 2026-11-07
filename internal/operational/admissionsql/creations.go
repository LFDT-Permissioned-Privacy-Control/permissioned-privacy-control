package admissionsql

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/identity"
)

var _ a.CreationRawTx = (*rawTx)(nil)
var _ a.CreationIntentStore = (*Store)(nil)

func (t *rawTx) GetWitness(id a.Digest) (a.Witness, bool, error) {
	o, found, err := t.GetOrigin()
	if err != nil {
		return a.Witness{}, false, err
	}
	if !found || o.Actor != t.scope.Actor || o.Organization != t.scope.Organization {
		return a.Witness{}, false, a.ErrConflict
	}
	if o.Primary.ID == id {
		return o.Primary, true, nil
	}
	var scan witnessScan
	err = t.tx.QueryRow(t.ctx, `SELECT `+witnessColumns+` FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1 AND tx_hash=$2 AND witness_id=$3`, t.scope.Network[:], t.scope.Hash[:], id[:]).Scan(scan.destinations()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return a.Witness{}, false, nil
	}
	if err != nil {
		return a.Witness{}, false, a.ErrUnavailable
	}
	w, err := scan.finish()
	return w, err == nil, err
}

type creationRef struct {
	seed, plan, manifest, runtime a.Digest
	kind                          string
	branch                        int
	wallet                        *a.CreationWalletAuthority
	anchor                        common.Hash
	number, timestamp             uint64
	profile                       string
	at                            time.Time
}

func (r creationRef) equal(i a.CreationIntent, kind string, manifest, runtime a.Digest) bool {
	wallet := r.wallet == nil && i.Wallet == nil || r.wallet != nil && i.Wallet != nil && *r.wallet == *i.Wallet
	if kind == "FACTORY" {
		wallet = r.wallet == nil
	}
	return r.kind == kind && r.plan == i.PlanDigest && r.seed == i.SeedDigest(kind) && r.manifest == manifest && r.runtime == runtime && r.anchor == i.Anchor.Hash && r.number == i.Anchor.Number && r.timestamp == i.Anchor.Timestamp && r.profile == i.Anchor.Profile && wallet
}

func (t *rawTx) creationRefs() ([]creationRef, error) {
	rows, err := t.tx.Query(t.ctx, `SELECT seed_digest,plan_digest,kind,branch,wallet_actor,wallet_org::text,witness_id,anchor_hash,anchor_number::text,anchor_timestamp::text,evidence_profile,manifest_digest,runtime_digest,captured_at FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 AND tx_hash=$2 ORDER BY kind,branch LIMIT 17`, t.scope.Network[:], t.scope.Hash[:])
	if err != nil {
		return nil, a.ErrUnavailable
	}
	defer rows.Close()
	refs := []creationRef{}
	branches := map[string]map[int]bool{}
	for rows.Next() {
		var r creationRef
		var seed, plan, witness, anchor, manifest, runtime []byte
		var actor, org *string
		var number, timestamp string
		if rows.Scan(&seed, &plan, &r.kind, &r.branch, &actor, &org, &witness, &anchor, &number, &timestamp, &r.profile, &manifest, &runtime, &r.at) != nil || len(seed) != 32 || len(plan) != 32 || len(anchor) != 32 || len(manifest) != 32 || len(runtime) != 32 || r.at.IsZero() || r.branch < 1 || r.branch > a.MaxCreationRefsPerBranch {
			return nil, a.ErrCoverage
		}
		copy(r.seed[:], seed)
		copy(r.plan[:], plan)
		copy(r.anchor[:], anchor)
		copy(r.manifest[:], manifest)
		copy(r.runtime[:], runtime)
		var parseErr error
		r.number, parseErr = strconv.ParseUint(number, 10, 64)
		if parseErr != nil {
			return nil, a.ErrCoverage
		}
		r.timestamp, parseErr = strconv.ParseUint(timestamp, 10, 64)
		if parseErr != nil {
			return nil, a.ErrCoverage
		}
		if r.kind == "WALLET" {
			if actor == nil || org == nil || !identity.ValidActorID(*actor) || !a.ValidUUID(*org) || len(witness) != 32 {
				return nil, a.ErrCoverage
			}
			var id a.Digest
			copy(id[:], witness)
			r.wallet = &a.CreationWalletAuthority{Actor: *actor, Organization: *org, Witness: id}
		} else if r.kind != "FACTORY" || actor != nil || org != nil || len(witness) != 0 {
			return nil, a.ErrCoverage
		}
		if branches[r.kind] == nil {
			branches[r.kind] = map[int]bool{}
		}
		if branches[r.kind][r.branch] {
			return nil, a.ErrCoverage
		}
		branches[r.kind][r.branch] = true
		refs = append(refs, r)
		if len(refs) > 2*a.MaxCreationRefsPerBranch {
			return nil, a.ErrCoverage
		}
	}
	if rows.Err() != nil {
		return nil, a.ErrUnavailable
	}
	for _, kind := range branches {
		for ordinal := 1; ordinal <= len(kind); ordinal++ {
			if !kind[ordinal] {
				return nil, a.ErrCoverage
			}
		}
	}
	return refs, nil
}

func (t *rawTx) PutCreationIntent(i a.CreationIntent) (a.CreationIntentReceipt, error) {
	return t.putCreationIntent(i, nil)
}
func (t *rawTx) putCreationIntent(i a.CreationIntent, coverage *creationfacts.CoverageRecord) (a.CreationIntentReceipt, error) {
	validator := i.Validate
	if coverage != nil {
		validator = i.ValidateCaptured
	}
	plan, err := validator(t.scope)
	version := 1
	coverageBytes := 0
	if coverage != nil {
		version = 2
		raw, e := coverage.Canonical()
		if e != nil {
			return a.CreationIntentReceipt{}, a.ErrInvalid
		}
		coverageBytes = len(raw)
	}
	if err != nil {
		return a.CreationIntentReceipt{}, err
	}
	manifest, _ := a.ParseDigest(plan.Manifest)
	runtime, _ := a.ParseDigest(plan.Runtime)
	if i.Wallet != nil {
		w, found, err := t.GetWitness(i.Wallet.Witness)
		if err != nil {
			return a.CreationIntentReceipt{}, err
		}
		if !found || w.AnchorHash != i.Anchor.Hash || w.AnchorNumber != i.Anchor.Number || w.AnchorTimestamp != i.Anchor.Timestamp || w.EvidenceProfile != i.Anchor.Profile {
			return a.CreationIntentReceipt{}, a.ErrConflict
		}
	}
	var oldPlan []byte
	err = t.tx.QueryRow(t.ctx, `SELECT CASE WHEN octet_length(payload)<=65536 THEN payload ELSE NULL END FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND tx_hash=$2 AND plan_digest=$3`, t.scope.Network[:], t.scope.Hash[:], i.PlanDigest[:]).Scan(&oldPlan)
	newPlan := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !newPlan {
		return a.CreationIntentReceipt{}, a.ErrUnavailable
	}
	if !newPlan && !bytes.Equal(oldPlan, i.Plan) {
		return a.CreationIntentReceipt{}, a.ErrConflict
	}
	refs, err := t.creationRefs()
	if err != nil {
		return a.CreationIntentReceipt{}, err
	}
	var generation int64
	err = t.tx.QueryRow(t.ctx, `SELECT generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, t.scope.Network[:], t.scope.Hash[:]).Scan(&generation)
	newWork := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !newWork {
		return a.CreationIntentReceipt{}, a.ErrUnavailable
	}
	if newWork != (len(refs) == 0) || (!newWork && generation < 1) {
		return a.CreationIntentReceipt{}, a.ErrCoverage
	}
	planReferenced := false
	for _, r := range refs {
		if r.plan == i.PlanDigest {
			planReferenced = true
		}
	}
	if !newPlan && !planReferenced {
		return a.CreationIntentReceipt{}, a.ErrCoverage
	}
	requested := []string{}
	if i.Wallet != nil {
		requested = append(requested, "WALLET")
	}
	if i.Factory {
		requested = append(requested, "FACTORY")
	}
	newRefs := []creationRef{}
	var walletSeed, factorySeed *a.Digest
	for _, kind := range requested {
		seed := i.SeedDigest(kind)
		if kind == "WALLET" {
			copy := seed
			walletSeed = &copy
		} else {
			copy := seed
			factorySeed = &copy
		}
		matched := false
		count := 0
		for _, r := range refs {
			if r.kind == kind {
				count++
			}
			if r.seed == seed {
				if !r.equal(i, kind, manifest, runtime) {
					return a.CreationIntentReceipt{}, a.ErrConflict
				}
				if coverage != nil {
					if err := t.originalCoverage(seed, i.Anchor.Hash, i.Anchor.Number); err != nil {
						return a.CreationIntentReceipt{}, err
					}
				}
				matched = true
			}
		}
		if matched {
			continue
		}
		if count >= a.MaxCreationRefsPerBranch {
			return a.CreationIntentReceipt{}, a.ErrConflict
		}
		r := creationRef{seed: seed, plan: i.PlanDigest, manifest: manifest, runtime: runtime, kind: kind, branch: count + 1, anchor: i.Anchor.Hash, number: i.Anchor.Number, timestamp: i.Anchor.Timestamp, profile: i.Anchor.Profile, at: i.CapturedAt}
		if kind == "WALLET" {
			r.wallet = i.Wallet
		}
		newRefs = append(newRefs, r)
	}
	receipt := a.CreationIntentReceipt{Seeds: a.CreationSeedSet(walletSeed, factorySeed)}
	if len(newRefs) == 0 {
		return receipt, nil
	}
	if !newWork && generation == math.MaxInt64 {
		return a.CreationIntentReceipt{}, a.ErrConflict
	}
	// The shared hash lock is already held. This final lock covers aggregate
	// quotas across DIFFERENT hashes. No earlier lock class or network follows.
	var usage a.CreationLimits
	if err := t.tx.QueryRow(t.ctx, `SELECT work_count,plan_count,plan_bytes,wallet_ref_count,factory_ref_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1 FOR UPDATE`, t.scope.Network[:]).Scan(&usage.Work, &usage.Plans, &usage.Bytes, &usage.WalletRefs, &usage.FactoryRefs); err != nil {
		return a.CreationIntentReceipt{}, a.ErrUnavailable
	}
	if coverage != nil {
		rows, bytes, err := t.coverageUsage(t.ctx)
		limits := t.observerLimits
		addRows := int64(len(newRefs))
		addBytes := addRows * int64(coverageBytes)
		if err != nil || !limits.Valid() || rows < 0 || bytes < 0 || rows > limits.CoverageRows-addRows || bytes > limits.CoverageBytes-addBytes {
			return a.CreationIntentReceipt{}, a.ErrUnavailable
		}
	}
	delta := a.CreationLimits{}
	if newWork {
		delta.Work = 1
	}
	if newPlan {
		delta.Plans = 1
		delta.Bytes = int64(len(i.Plan))
	}
	for _, r := range newRefs {
		if r.kind == "WALLET" {
			delta.WalletRefs++
		} else {
			delta.FactoryRefs++
		}
	}
	limits := t.storeCreationLimits()
	if !limits.Valid() || usage.Work < 0 || usage.Plans < 0 || usage.Bytes < 0 || usage.WalletRefs < 0 || usage.FactoryRefs < 0 || usage.Work > limits.Work-delta.Work || usage.Plans > limits.Plans-delta.Plans || usage.Bytes > limits.Bytes-delta.Bytes || usage.WalletRefs > limits.WalletRefs-delta.WalletRefs || usage.FactoryRefs > limits.FactoryRefs-delta.FactoryRefs {
		return a.CreationIntentReceipt{}, a.ErrUnavailable
	}
	if newPlan {
		_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.creation_plans(network_key,tx_hash,plan_digest,version,payload,entry_count,root_org,manifest_digest,runtime_digest,chain_id,evidence_profile,created_at)VALUES($1,$2,$3,$12,$4,$5,$6::uuid,$7,$8,$9,$10,$11)`, t.scope.Network[:], t.scope.Hash[:], i.PlanDigest[:], i.Plan, len(plan.Entries), plan.RootOrg, manifest[:], runtime[:], plan.Chain, plan.Evidence, i.CapturedAt, version)
		if err != nil {
			return a.CreationIntentReceipt{}, dbError(err)
		}
	}
	for _, r := range newRefs {
		var actor, org, witness any
		if r.wallet != nil {
			actor, org, witness = r.wallet.Actor, r.wallet.Organization, r.wallet.Witness[:]
		}
		_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.creation_authority_refs(network_key,tx_hash,seed_digest,plan_digest,kind,branch,wallet_actor,wallet_org,witness_id,anchor_hash,anchor_number,anchor_timestamp,evidence_profile,manifest_digest,runtime_digest,captured_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8::uuid,$9,$10,$11::numeric,$12::numeric,$13,$14,$15,$16)`, t.scope.Network[:], t.scope.Hash[:], r.seed[:], r.plan[:], r.kind, r.branch, actor, org, witness, r.anchor[:], strconv.FormatUint(r.number, 10), strconv.FormatUint(r.timestamp, 10), r.profile, r.manifest[:], r.runtime[:], r.at)
		if err != nil {
			return a.CreationIntentReceipt{}, dbError(err)
		}
	}
	if coverage != nil {
		for _, r := range newRefs {
			if err := t.insertCoverage(r.seed, *coverage); err != nil {
				return a.CreationIntentReceipt{}, err
			}
		}
	}
	if newWork {
		_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.creation_work(network_key,tx_hash,generation,created_at,updated_at)VALUES($1,$2,1,$3,$3)`, t.scope.Network[:], t.scope.Hash[:], i.CapturedAt)
	} else {
		var next int64
		err = t.tx.QueryRow(t.ctx, `UPDATE ops_admission_v2.creation_work SET generation=generation+1,updated_at=GREATEST(updated_at,$4) WHERE network_key=$1 AND tx_hash=$2 AND generation=$3 RETURNING generation`, t.scope.Network[:], t.scope.Hash[:], generation, i.CapturedAt).Scan(&next)
	}
	if err != nil {
		return a.CreationIntentReceipt{}, dbError(err)
	}
	if coverage != nil {
		_, err = t.tx.Exec(t.ctx, `UPDATE ops_admission_v2.creation_capacity SET work_count=work_count+$2,plan_count=plan_count+$3,plan_bytes=plan_bytes+$4,wallet_ref_count=wallet_ref_count+$5,factory_ref_count=factory_ref_count+$6,capture_coverage_count=capture_coverage_count+$7,capture_coverage_bytes=capture_coverage_bytes+$8 WHERE network_key=$1`, t.scope.Network[:], delta.Work, delta.Plans, delta.Bytes, delta.WalletRefs, delta.FactoryRefs, len(newRefs), len(newRefs)*coverageBytes)
	} else {
		_, err = t.tx.Exec(t.ctx, `UPDATE ops_admission_v2.creation_capacity SET work_count=work_count+$2,plan_count=plan_count+$3,plan_bytes=plan_bytes+$4,wallet_ref_count=wallet_ref_count+$5,factory_ref_count=factory_ref_count+$6 WHERE network_key=$1`, t.scope.Network[:], delta.Work, delta.Plans, delta.Bytes, delta.WalletRefs, delta.FactoryRefs)
	}
	if err != nil {
		return a.CreationIntentReceipt{}, dbError(err)
	}
	t.effects = true
	return receipt, nil
}

func (t *rawTx) storeCreationLimits() a.CreationLimits { return t.creationLimits }
