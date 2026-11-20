package explorerindex

import (
	"bytes"
	"encoding/json"
	"testing"

	pb "privacy-proxy/gen/go/chain_indexer/v2"
)

func TestTokenMetadataPassRetainsOptionalExactPriceAndSupply(t *testing.T) {
	supply, price := "1000000000000000000000000000000", "0.290000000000000001"
	input := &pb.Token{Key: &pb.CreationKey{Address: bytes.Repeat([]byte{1}, 20), BlockNumber: 12}, TotalSupply: &supply, UsdPrice: &price}
	row, err := tokenRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if json.Unmarshal(row.JSON, &values) != nil || values["total_supply"] != supply || values["usd_price"] != price {
		t.Fatal(string(row.JSON))
	}
	input.TotalSupply, input.UsdPrice = nil, nil
	row, err = tokenRecord(input)
	if err != nil || json.Unmarshal(row.JSON, &values) != nil || values["total_supply"] != nil || values["usd_price"] != nil {
		t.Fatal(string(row.JSON), err)
	}
}
