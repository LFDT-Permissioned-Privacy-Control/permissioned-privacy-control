package indexerclient

import (
	"context"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// Ported methods. Each one overrides the corresponding embedded *explorer.Store
// method by calling the chain-indexer gRPC API and mapping the response.
//
// Methods NOT listed here are served by the embedded *Store as-is — that is
// the staged cutover strategy. As methods are added here, the gRPC path
// takes over automatically because of Go method shadowing on embedded types.

// ----- Blocks -----

func (b *Backend) GetBlock(ctx context.Context, number uint64) (*explorer.Block, error) {
	resp, err := b.client.GetBlock(ctx, &indexerv1.GetBlockRequest{
		Selector: &indexerv1.GetBlockRequest_Number{Number: number},
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapBlock(resp), nil
}

func (b *Backend) GetBlockByHash(ctx context.Context, hash string) (*explorer.Block, error) {
	resp, err := b.client.GetBlock(ctx, &indexerv1.GetBlockRequest{
		Selector: &indexerv1.GetBlockRequest_Hash{Hash: hash},
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapBlock(resp), nil
}

func (b *Backend) GetLatestBlockNumber(ctx context.Context) (uint64, error) {
	resp, err := b.client.GetLatestBlockNumber(ctx, &indexerv1.Empty{})
	if err != nil {
		return 0, err
	}
	return resp.GetNumber(), nil
}

// ----- Transactions -----

func (b *Backend) GetTransaction(ctx context.Context, hash string) (*explorer.Transaction, error) {
	resp, err := b.client.GetTransaction(ctx, &indexerv1.GetTransactionRequest{Hash: hash})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapTransaction(resp), nil
}

func (b *Backend) GetTransactionWithCategories(ctx context.Context, hash string) (*explorer.Transaction, error) {
	// The indexer's GetTransaction always returns categories (materialized
	// column from RD-855 Phase 2.9). Same RPC; separate method for symmetry
	// with the legacy Store API.
	return b.GetTransaction(ctx, hash)
}

// ----- Address -----

func (b *Backend) GetAddressStats(ctx context.Context, address string) (*explorer.AddressStats, error) {
	resp, err := b.client.GetAddress(ctx, &indexerv1.GetAddressRequest{Address: address})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return mapAddressStats(resp), nil
}

// ----- Stats / sync -----

func (b *Backend) GetChainStats(ctx context.Context) (*explorer.ChainStats, error) {
	resp, err := b.client.GetChainStats(ctx, &indexerv1.Empty{})
	if err != nil {
		return nil, err
	}
	return mapChainStats(resp), nil
}

func (b *Backend) GetSyncStatus(ctx context.Context) (*explorer.SyncStatus, error) {
	resp, err := b.client.GetSyncStatus(ctx, &indexerv1.Empty{})
	if err != nil {
		return nil, err
	}
	return mapSyncStatus(resp), nil
}
