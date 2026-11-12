package v2demo

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/operational/admissionsql"
	vs "privacy-proxy/internal/operational/v2server"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policyprofiles"
)

// Check reads actual node, indexer and observer results. It writes no source or
// indexed row and does not turn a stored association into permission authority.
func Check(parent context.Context, root, transaction, contract string, block uint64) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil || !s.Configured || len(transaction) != 66 || common.HexToHash(transaction).Hex() != transaction || strings.ToLower(contract) != s.TargetContract {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	node, e := ethclient.DialContext(ctx, s.RPCURL())
	if e != nil {
		return e
	}
	defer node.Close()
	hash := common.HexToHash(transaction)
	receipt, e := node.TransactionReceipt(ctx, hash)
	if e != nil || receipt.Status != 1 || receipt.BlockNumber.Uint64() != block {
		return ErrInvalid
	}
	header, e := node.HeaderByNumber(ctx, new(big.Int).SetUint64(block))
	if e != nil || header.Hash() != receipt.BlockHash {
		return ErrInvalid
	}
	rawDigest, e := os.ReadFile(s.file("ops/server.sha256"))
	if e != nil {
		return e
	}
	cfg, e := vs.ReadConfig(s.file("ops/server.json"), strings.TrimSpace(string(rawDigest)))
	if e != nil {
		return e
	}
	options, _, e := policyprofiles.DeliveryOptions(policybundle.RuntimeCreationObservedProfileID)
	if e != nil {
		return e
	}
	snapshot, e := policybundle.LoadDirectory(ctx, policybundle.Selection{Directory: cfg.Core.Directory, ExpectedManifestDigest: policybundle.Digest(cfg.Core.ManifestDigest), ExpectedEnvironment: Environment, ExpectedChainID: ChainID}, options)
	if e != nil {
		return e
	}
	ids, _ := snapshot.Identity()
	metadata, _, e := walletMetadata(s)
	if e != nil {
		return e
	}
	who := metadata.Personas[1]
	actor, e := ids.SourceActorID(identity.SourceIdentity{ProfileID: who.ProfileID, Kind: identity.Human, Authority: "privado", Subject: who.HolderDID})
	if e != nil {
		return e
	}
	index, e := pgx.Connect(ctx, s.dsn("index", "postgres"))
	if e != nil {
		return e
	}
	defer index.Close(ctx)
	facts, e := pgx.Connect(ctx, s.dsn("admission", "postgres"))
	if e != nil {
		return e
	}
	defer facts.Close(ctx)
	binding := admission.NetworkBinding{Environment: Environment, ChainID: ChainID, GenesisHash: s.GenesisHash, DeploymentID: Deployment}
	key, _ := binding.Key()
	target := common.HexToAddress(contract)
	for ctx.Err() == nil {
		var indexed bool
		var synced int64
		e = index.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.transactions t JOIN public.blocks b ON t.block_number=b.number WHERE lower(t.hash)=$1 AND t.block_number=$2 AND lower(b.hash)=$3)`, transaction, int64(block), receipt.BlockHash.Hex()).Scan(&indexed)
		if e != nil {
			return e
		}
		if e = index.QueryRow(ctx, `SELECT last_indexed_block FROM public.sync_status ORDER BY id LIMIT 1`).Scan(&synced); e != nil {
			return e
		}
		status, e := admissionsql.CreationObserverStatus(ctx, s.dsn("admission", "postgres"), binding)
		if e != nil {
			return e
		}
		var birthNumber int64
		var birthHash, outputHash []byte
		var outputLength int
		e = facts.QueryRow(ctx, `SELECT b.inclusion_number,b.inclusion_hash,b.output_hash,b.output_length FROM ops_admission_v2.creation_births b JOIN ops_admission_v2.creation_authority_associations a USING(network_key,tx_hash,inclusion_hash,actual_creation_record) WHERE b.network_key=$1 AND b.address=$2 AND a.namespace=$3::uuid AND a.kind='WALLET' AND a.wallet_actor=$4 ORDER BY b.inclusion_number DESC LIMIT 1`, key[:], target[:], Organization, actor).Scan(&birthNumber, &birthHash, &outputHash, &outputLength)
		if e != nil && e != pgx.ErrNoRows {
			return e
		}
		if indexed && synced >= int64(block) && status.Ready && status.CaptureReady && status.Head.Number >= block && status.LeaseRemainingTTL > 0 && e == nil {
			original, e := node.HeaderByNumber(ctx, big.NewInt(birthNumber))
			if e != nil || !bytes.Equal(original.Hash().Bytes(), birthHash) {
				return ErrInvalid
			}
			code, e := node.CodeAt(ctx, target, big.NewInt(birthNumber))
			if e != nil || len(code) != outputLength || !bytes.Equal(crypto.Keccak256(code), outputHash) {
				return ErrInvalid
			}
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("actual indexer/observer did not qualify transaction and creation within the bounded wait")
}
