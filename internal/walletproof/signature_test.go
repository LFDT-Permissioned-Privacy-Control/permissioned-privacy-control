package walletproof

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestTextHashCompatibility(t *testing.T) {
	for _, s := range []string{"", "hello", "Здравствуй, мир", "\ufeffwallet\r\nmessage", string([]byte{0xff, 0x00, 0x80}), strings.Repeat("é", 4097)} {
		if !bytes.Equal(HashMessage(s), accounts.TextHash([]byte(s))) {
			t.Fatal("EIP191 byte-length/hash mismatch")
		}
	}
}

func TestStrictProofAndLegacyMalleabilityBoundary(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := "OPS deterministic test message"
	sig, err := crypto.Sign(HashMessage(message), key)
	if err != nil {
		t.Fatal(err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	for _, offset := range []byte{0, 27} {
		raw := bytes.Clone(sig)
		raw[64] += offset
		got, err := RecoverV2(message, raw)
		if err != nil || got != want {
			t.Fatal("valid EIP191 signature", err)
		}
	}
	malleable := bytes.Clone(sig)
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(crypto.S256().Params().N, s)
	s.FillBytes(malleable[32:64])
	malleable[64] ^= 1
	if _, err := RecoverV2(message, malleable); err == nil {
		t.Fatal("highS accepted in new proof")
	}
	if got, err := RecoverLegacy(message, "0x"+hex.EncodeToString(malleable)); err != nil || got != want {
		t.Fatal("legacy behavior changed", err)
	}
	for _, v := range []byte{2, 26, 29, 35, 255} {
		bad := bytes.Clone(sig)
		bad[64] = v
		if _, err := RecoverV2(message, bad); err == nil {
			t.Fatal("unsupported recovery id", v)
		}
	}
	if _, err := Signature("0x" + strings.Repeat("0", 130)); err == nil {
		t.Fatal("zero scalars")
	}
	if got, err := RecoverV2(message+"!", sig); err == nil && got == want {
		t.Fatal("signature not message-bound")
	}
}
func TestMessageDelimitersAndDuration(t *testing.T) {
	f := MessageFields{Origin: "https://ops.test", Namespace: "sha256:" + strings.Repeat("1", 64), Actor: "actor", Address: "0x" + strings.Repeat("0", 40), Nonce: strings.Repeat("1", 64), IssuedAt: time.Unix(1800000000, 0), ExpiresAt: time.Unix(1800000300, 0)}
	message, err := Message(f)
	if err != nil || strings.HasSuffix(message, "\n") || strings.Count(message, "\n") != 9 {
		t.Fatal("message template", err)
	}
	f.Actor = "actor\nAddress: forged"
	if _, err := Message(f); err == nil {
		t.Fatal("line injection")
	}
	f.Actor = "actor"
	f.ExpiresAt = f.ExpiresAt.Add(time.Second)
	if _, err := Message(f); err == nil {
		t.Fatal("excess duration")
	}
}
