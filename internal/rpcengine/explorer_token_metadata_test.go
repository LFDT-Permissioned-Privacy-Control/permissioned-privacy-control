package rpcengine

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/explorerquery"
	wire "privacy-proxy/internal/explorerv2data"
)

func tokenMetadataProjection(t *testing.T, level explorerdata.VisibilityLevel, supply, price any) (any, bool, error) {
	t.Helper()
	address := "0x" + strings.Repeat("1", 40)
	raw, err := json.Marshal(map[string]any{"address": address, "symbol": "BANK", "decimals": 18, "token_type": "ERC20", "block_number": "12", "created_at": "2026-11-20T00:00:00Z", "total_supply": supply, "usd_price": price, "holder_count": "999999999", "transfer_count": "888888888"})
	if err != nil {
		t.Fatal(err)
	}
	render := &explorerRender{result: &ExplorerOperationResult{}, detailed: map[string]explorerdata.AddressVisibility{address: {Level: level}}}
	return render.other(explorerquery.Record{Family: explorerquery.Tokens, JSON: raw})
}

func TestFullTokenRetainsExactIndexedSupplyAndPriceWithoutRawGlobalCounts(t *testing.T) {
	maximum := "115792089237316195423570985008687907853269984665640564039457584007913129639935"
	value, visible, err := tokenMetadataProjection(t, explorerdata.VisibilityFull, maximum, "0.290000000000000001")
	if err != nil || !visible {
		t.Fatal(value, visible, err)
	}
	token := value.(wire.Token)
	if token.TotalSupply == nil || string(*token.TotalSupply) != maximum || token.USDPrice == nil || string(*token.USDPrice) != "0.290000000000000001" || token.HolderCount != nil || token.TransferCount != nil {
		t.Fatal(token)
	}
	for _, level := range []explorerdata.VisibilityLevel{explorerdata.VisibilityRedacted, explorerdata.VisibilityHidden} {
		value, visible, err := tokenMetadataProjection(t, level, "invalid-private-supply", "invalid-private-price")
		if err != nil || visible || value != nil {
			t.Fatal("metadata escaped Full gate", value, visible, err)
		}
	}
}

func TestUnknownTokenMetadataStaysAbsentAndZeroStaysKnown(t *testing.T) {
	for _, test := range []struct {
		supply, price any
		known         bool
	}{{nil, nil, false}, {"0", "0", true}} {
		value, visible, err := tokenMetadataProjection(t, explorerdata.VisibilityFull, test.supply, test.price)
		if err != nil || !visible {
			t.Fatal(value, visible, err)
		}
		token := value.(wire.Token)
		if (token.TotalSupply != nil) != test.known || (token.USDPrice != nil) != test.known {
			t.Fatal(token)
		}
	}
}

func TestMalformedIndexedSupplyOrPriceNeverBecomesDisplayMetadata(t *testing.T) {
	for _, supply := range []string{"-1", "01", "1.5", "1e3", "115792089237316195423570985008687907853269984665640564039457584007913129639936"} {
		if _, _, err := tokenMetadataProjection(t, explorerdata.VisibilityFull, supply, nil); err == nil {
			t.Fatal("accepted supply", supply)
		}
	}
	for _, price := range []any{"-0.1", "00.1", "1e3", "NaN", "0.", ".5", strings.Repeat("1", 129), 0.29} {
		if _, _, err := tokenMetadataProjection(t, explorerdata.VisibilityFull, nil, price); err == nil {
			t.Fatal("accepted price", price)
		}
	}
}
