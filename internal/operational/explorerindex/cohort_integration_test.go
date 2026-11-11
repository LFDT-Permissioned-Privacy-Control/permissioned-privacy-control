package explorerindex

import (
	"encoding/json"
	"privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/explorerquery"
	"strings"
	"testing"
)

func TestActualCohortContinuationLatestBalancesAndChangedContext(t *testing.T) {
	f := indexFixture(t)
	r := f.open(t)
	hash := func(c string) string { return "0x" + strings.Repeat(c, 64) }
	address := func(c string) string { return "0x" + strings.Repeat(c, 40) }
	f.exec(t, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count) VALUES(0,$1,$1,1,0,30000000,0),(1,$2,$1,2,63000,30000000,3)`, hash("1"), hash("2"))
	for i := 0; i < 3; i++ {
		f.exec(t, `INSERT INTO transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data) VALUES($1,1,$2,$3,$4,340282366920938463463374607431768211456,21000,3,1,'0x')`, hash(string(rune('3'+i))), i, address("a"), address("b"))
	}
	f.exec(t, `INSERT INTO balances(address,token_address,block_number,balance) VALUES($1,$2,0,99),($1,$2,1,0),($1,$3,0,13)`, address("a"), address("c"), address("d"))
	fence, err := admissionsharedata.NewFence(t.Context(), admissionsharedata.MaxOperationTime)
	if err != nil {
		t.Fatal(err)
	}
	q := explorerquery.Query{Family: explorerquery.Transactions, RawLimit: 1, Fence: fence}
	pass, err := r.ReadCohort(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	data := pass.Data()
	if data.Exhausted || len(data.Rows) != 2 || data.Rows[0].Position.Index != 2 || len(data.Context) != 2 {
		t.Fatal("raw bounded cohort/context", len(data.Rows), len(data.Context), data.Exhausted)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data.Rows[0].JSON, &fields) != nil || string(fields["value"]) != `"340282366920938463463374607431768211456"` {
		t.Fatal("lossless DB quantity", string(data.Rows[0].JSON))
	}
	next := q
	next.Upper = data.Upper
	next.After = &data.Rows[0].Position
	following, err := r.ReadCohort(t.Context(), next)
	if err != nil || following.Data().Rows[0].Position.Index != 1 {
		t.Fatal("same-block keyset continuation", err)
	}
	balance, err := r.ReadCohort(t.Context(), explorerquery.Query{Family: explorerquery.Balances, Address: address("a"), RawLimit: 10, Fence: fence})
	if err != nil {
		t.Fatal(err)
	}
	if len(balance.Data().Rows) != 1 || balance.Data().Rows[0].Position.Hash != address("d") {
		t.Fatal("old positive resurrected after latest zero")
	}
	if err = r.Recheck(t.Context(), pass); err != nil {
		t.Fatal("unchanged captured cohort", err)
	}
	f.exec(t, `UPDATE transactions SET value=value+1 WHERE hash=$1`, data.Rows[0].Position.Hash)
	if err = r.Recheck(t.Context(), pass); err != explorerquery.ErrConflict {
		t.Fatal("changed captured row not rejected", err)
	}
}
