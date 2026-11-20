package explorerquery

import "testing"

func TestNormalizeTransferKindClosedAndFamilyBound(t *testing.T) {
	for _, kind := range []TokenKind{"", TokenKindERC20, TokenKindERC721, TokenKindERC1155} {
		if _, e := Normalize(Query{Family: Transfers, RawLimit: 1, TokenKind: kind}); e != nil {
			t.Fatal(kind, e)
		}
	}
	for _, q := range []Query{{Family: Transfers, RawLimit: 1, TokenKind: "erc20"}, {Family: Transfers, RawLimit: 1, TokenKind: "ERC777"}, {Family: Transactions, RawLimit: 1, TokenKind: TokenKindERC20}} {
		if _, e := Normalize(q); e == nil {
			t.Fatal("invalid kind accepted", q)
		}
	}
}
