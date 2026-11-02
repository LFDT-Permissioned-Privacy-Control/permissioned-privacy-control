package perfgate

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Sender is one linked wallet owned by user User.
type Sender struct {
	Key     *ecdsa.PrivateKey
	Address string
	User    int
}

// Tx is one pre-signed, unique transaction and its request body.
type Tx struct {
	Hash   string
	Sender int
	Nonce  uint64
	Body   []byte
}

// NewSenders derives users × perUser deterministic test keys from seed. The
// keys are local load-test fixtures and must never hold value elsewhere.
func NewSenders(seed string, users, perUser int) ([]Sender, error) {
	out := make([]Sender, 0, users*perUser)
	for u := 0; u < users; u++ {
		for w := 0; w < perUser; w++ {
			var index [8]byte
			binary.BigEndian.PutUint64(index[:], uint64(len(out)))
			key, err := crypto.ToECDSA(crypto.Keccak256([]byte("perfgate-sender"), []byte(seed), index[:]))
			if err != nil {
				return nil, err
			}
			out = append(out, Sender{Key: key, Address: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()), User: u})
		}
	}
	return out, nil
}

// SignWorkload signs total EIP-1559 value transfers, round-robin over senders
// so each sender's consecutive nonces are offered in order, using workers
// goroutines. Signing is outside every timed phase.
func SignWorkload(senders []Sender, chainID uint64, total, workers int) ([]Tx, error) {
	if len(senders) == 0 || total <= 0 {
		return nil, fmt.Errorf("empty workload")
	}
	if workers <= 0 {
		workers = 1
	}
	chain := new(big.Int).SetUint64(chainID)
	signer := types.LatestSignerForChainID(chain)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000f2a7e")
	out := make([]Tx, total)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < total; i += workers {
				s := i % len(senders)
				nonce := uint64(i / len(senders))
				tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: chain, Nonce: nonce, GasTipCap: big.NewInt(1_000_000), GasFeeCap: big.NewInt(3_000_000_000), Gas: 21_000, To: &recipient, Value: big.NewInt(1)}), signer, senders[s].Key)
				if err != nil {
					errs <- err
					return
				}
				raw, err := tx.MarshalBinary()
				if err != nil {
					errs <- err
					return
				}
				out[i] = Tx{Hash: strings.ToLower(tx.Hash().Hex()), Sender: s, Nonce: nonce,
					Body: []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(i) + `,"method":"eth_sendRawTransaction","params":["0x` + hex.EncodeToString(raw) + `"]}`)}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	return out, nil
}
