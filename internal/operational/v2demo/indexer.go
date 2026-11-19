package v2demo

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
)

// The isolated demo selects a loopback-only trusted service endpoint. Even
// offline health/barrier helpers read chain facts through the indexer API.
func indexerClient(s State) (*grpc.ClientConn, indexerv1.IndexerServiceClient, error) {
	conn, err := grpc.NewClient(s.indexerAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)))
	if err != nil {
		return nil, nil, err
	}
	return conn, indexerv1.NewIndexerServiceClient(conn), nil
}
