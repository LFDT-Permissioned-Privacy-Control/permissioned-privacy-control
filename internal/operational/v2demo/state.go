// Package v2demo bootstraps an isolated, explicitly public local demo. It is an
// offline tool and is never imported by the serving commands or pure Core.
package v2demo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	vs "privacy-proxy/internal/operational/v2server"
)

const Organization = "11111111-1111-4111-8111-111111111111"
const Admin = "22222222-2222-4222-8222-222222222222"
const Deployer = "33333333-3333-4333-8333-333333333333"
const Reader = "44444444-4444-4444-8444-444444444444"
const ChainID = "31337"
const Environment = "demo"
const Deployment = "native-v2-local-demo"

var ErrInvalid = errors.New("invalid isolated V2 demo state")

type Ports struct {
	OPS            int `json:"ops"`
	Explorer       int `json:"explorer"`
	Wallet         int `json:"wallet"`
	Postgres       int `json:"postgres"`
	RPC            int `json:"rpc"`
	Engine         int `json:"engine"`
	Indexer        int `json:"indexer"`
	IndexerGRPC    int `json:"indexerGRPC"`
	ExplorerAPI    int `json:"explorerAPI"`
	IndexerMetrics int `json:"indexerMetrics"`
}
type State struct {
	Version            int               `json:"version"`
	Root               string            `json:"root"`
	CreatedAt          int64             `json:"createdAt"`
	Ports              Ports             `json:"ports"`
	Secrets            map[string]string `json:"secrets"`
	Epochs             map[string]string `json:"epochs"`
	Configured         bool              `json:"configured"`
	GenesisHash        string            `json:"genesisHash"`
	TargetContract     string            `json:"targetContract"`
	ActivityGeneration string            `json:"activityGeneration"`
	ReaderGrant        bool              `json:"readerGrant"`
	WalletOutput       string            `json:"walletOutput"`
}

func (s State) OPSOrigin() string       { return fmt.Sprintf("https://localhost:%d", s.Ports.OPS) }
func (s State) ExplorerOrigin() string  { return fmt.Sprintf("https://localhost:%d", s.Ports.Explorer) }
func (s State) WalletOrigin() string    { return fmt.Sprintf("https://localhost:%d", s.Ports.Wallet) }
func (s State) RPCURL() string          { return fmt.Sprintf("http://127.0.0.1:%d", s.Ports.RPC) }
func (s State) file(name string) string { return filepath.Join(s.Root, name) }
func readState(root string) (State, error) {
	var s State
	b, e := os.ReadFile(filepath.Join(root, "private", "state.json"))
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	if e != nil || s.Version != 1 || s.Root != root {
		return s, ErrInvalid
	}
	return s, nil
}
func canonicalRoot(root string) (string, error) {
	if root == "" {
		return "", ErrInvalid
	}
	p, e := filepath.Abs(root)
	if e != nil || p == "/" || strings.ContainsAny(p, "\n\r,") {
		return "", ErrInvalid
	}
	return p, nil
}
func writeJSON(file string, value any) (vs.File, error) {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return vs.File{}, e
	}
	b = append(b, '\n')
	return writeBytes(file, b)
}
func writeBytes(file string, b []byte) (vs.File, error) {
	if e := os.MkdirAll(filepath.Dir(file), 0700); e != nil {
		return vs.File{}, e
	}
	temporary := file + "." + uuid.NewString()
	if e := os.WriteFile(temporary, b, 0600); e != nil {
		return vs.File{}, e
	}
	if e := os.Rename(temporary, file); e != nil {
		return vs.File{}, e
	}
	h := sha256.Sum256(b)
	return vs.File{Path: file, Digest: "sha256:" + hex.EncodeToString(h[:])}, nil
}
func save(s State) error { _, e := writeJSON(s.file("private/state.json"), s); return e }
func randomSecret(bytes int) string {
	b := make([]byte, bytes)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func scalarAddress(index int) string {
	k, _ := crypto.HexToECDSA(fmt.Sprintf("%064x", index))
	return strings.ToLower(crypto.PubkeyToAddress(k.PublicKey).Hex())
}
func freePort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func Init(root string) error {
	var e error
	root, e = canonicalRoot(root)
	if e != nil {
		return e
	}
	if old, e := readState(root); e == nil {
		if old.Version == 1 {
			if e := ensureTLS(old); e != nil {
				return e
			}
			return old.writeTail()
		}
		return ErrInvalid
	}
	if _, e := os.Stat(filepath.Join(root, "private", "state.json")); !os.IsNotExist(e) {
		return ErrInvalid
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return e
	}
	values := make([]int, 10)
	used := map[int]bool{}
	for i := range values {
		for {
			p, e := freePort()
			if e != nil {
				return e
			}
			if !used[p] {
				values[i] = p
				used[p] = true
				break
			}
		}
	}
	s := State{Version: 1, Root: root, CreatedAt: time.Now().Unix(), Ports: Ports{values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9]}, Secrets: map[string]string{}, Epochs: map[string]string{}, ReaderGrant: true}
	for _, name := range []string{"broker", "wallet", "admission", "sso", "disclosure", "index", "activitySource", "activityProducer"} {
		s.Epochs[name] = uuid.NewString()
	}
	for _, name := range []string{"DEMO_POSTGRES_PASSWORD", "DEMO_ROLE_SEED", "OPS_BROKER_REFRESH_DEMO", "OPS_BROKER_ENCRYPTION_DEMO", "DEMO_SSO_CONTEXT", "DEMO_SSO_GRANT", "DEMO_EXPLORER_SECRET", "DEMO_ADMISSION_CURSOR", "DEMO_ADMIN_CURSOR", "DEMO_RENDER_KEY", "DEMO_DATA_CURSOR", "DEMO_INDEX_CURSOR", "DEMO_INDEX_PSEUDONYM", "E2B_STATE", "E2B_TOKEN"} {
		s.Secrets[name] = randomSecret(32)
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	s.Secrets["DEMO_ACCESS_PRIVATE"] = base64.RawURLEncoding.EncodeToString(private)
	s.TargetContract = strings.ToLower(crypto.CreateAddress(crypto.PubkeyToAddress(mustKey(2).PublicKey), 0).Hex())
	if e = writeTLS(s); e != nil {
		return e
	}
	alloc := map[string]any{}
	for i := 1; i <= 5; i++ {
		alloc[strings.TrimPrefix(scalarAddress(i), "0x")] = map[string]string{"balance": "0x3635c9adc5dea00000"}
	}
	genesis := map[string]any{"config": map[string]any{"chainId": 31337, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0, "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": true, "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0}, "nonce": "0x0", "timestamp": fmt.Sprintf("0x%x", s.CreatedAt-60), "extraData": "0x", "gasLimit": "0x1c9c380", "difficulty": "0x0", "mixHash": "0x" + strings.Repeat("0", 64), "coinbase": "0x" + strings.Repeat("0", 40), "baseFeePerGas": "0x1", "alloc": alloc}
	if _, e = writeJSON(s.file("genesis.json"), genesis); e != nil {
		return e
	}
	engine := make([]byte, 32)
	if _, e = rand.Read(engine); e != nil {
		return e
	}
	if _, e = writeBytes(s.file("private/engine.jwt"), []byte(hex.EncodeToString(engine))); e != nil {
		return e
	}
	wallet := map[string]any{"listenHost": "127.0.0.1", "listenPort": s.Ports.Wallet, "origin": s.WalletOrigin(), "opsOrigin": s.OPSOrigin(), "opsUpstream": s.OPSOrigin(), "stateRpcUrl": s.WalletOrigin() + "/rpc", "tlsCertificateFile": s.file("tls.crt"), "tlsPrivateKeyFile": s.file("tls.key"), "outputDirectory": s.file("wallet-state")}
	if _, e = writeJSON(s.file("wallet.json"), wallet); e != nil {
		return e
	}
	if _, e = writeJSON(s.file("runtime.json"), map[string]any{"version": 1, "testOnly": true, "ports": s.Ports, "opsOrigin": s.OPSOrigin(), "explorerOrigin": s.ExplorerOrigin(), "walletOrigin": s.WalletOrigin(), "rpcUrl": s.RPCURL(), "chainId": ChainID, "organizationId": Organization, "targetContract": s.TargetContract}); e != nil {
		return e
	}
	if e = save(s); e != nil {
		return e
	}
	return s.writeTail()
}
func mustKey(index int) *ecdsa.PrivateKey {
	k, e := crypto.HexToECDSA(fmt.Sprintf("%064x", index))
	if e != nil {
		panic(e)
	}
	return k
}
func writeTLS(s State) error {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Isolated V2 demo CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "Isolated V2 demo localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	for name, key := range map[string]*ecdsa.PrivateKey{"private/ca.key": caKey, "tls.key": leafKey} {
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		if _, e = writeBytes(s.file(name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); e != nil {
			return e
		}
	}
	if _, e = writeBytes(s.file("ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); e != nil {
		return e
	}
	_, e = writeBytes(s.file("tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	return e
}

// RepairTLS replaces only incompatible demo TLS material. Normal restarts retain
// a valid P-256 CA and leaf byte-for-byte; identity signing keys and state never
// participate in this repair. Each file is atomically replaced, and validation
// of the entire set makes an interrupted multi-file repair safe to retry.
func RepairTLS(root string) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil {
		return e
	}
	return ensureTLS(s)
}

func ensureTLS(s State) error {
	if compatibleTLS(s) {
		return nil
	}
	return writeTLS(s)
}

func compatibleTLS(s State) bool {
	readPEM := func(name, kind string) []byte {
		raw, e := os.ReadFile(s.file(name))
		if e != nil {
			return nil
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
			return nil
		}
		return block.Bytes
	}
	ca, e := x509.ParseCertificate(readPEM("ca.crt", "CERTIFICATE"))
	if e != nil || !ca.IsCA || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 || ca.CheckSignatureFrom(ca) != nil {
		return false
	}
	leaf, e := x509.ParseCertificate(readPEM("tls.crt", "CERTIFICATE"))
	if e != nil || leaf.IsCA || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || leaf.CheckSignatureFrom(ca) != nil {
		return false
	}
	for _, item := range []struct {
		name string
		cert *x509.Certificate
	}{{"private/ca.key", ca}, {"tls.key", leaf}} {
		value, e := x509.ParsePKCS8PrivateKey(readPEM(item.name, "PRIVATE KEY"))
		if e != nil {
			return false
		}
		key, ok := value.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() || !key.PublicKey.Equal(item.cert.PublicKey) {
			return false
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); e != nil {
		return false
	}
	return leaf.VerifyHostname("127.0.0.1") == nil
}

func (s State) writeEnv(file string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if strings.ContainsAny(values[k], "\n\r") {
			return ErrInvalid
		}
		fmt.Fprintf(&b, "%s=%s\n", k, values[k])
	}
	_, e := writeBytes(s.file(file), []byte(b.String()))
	return e
}

func (s State) writePorts() error {
	return s.writeEnv("compose.env", map[string]string{"OPS_V2_DEMO_POSTGRES_PORT": fmt.Sprint(s.Ports.Postgres), "OPS_V2_DEMO_RETH_PORT": fmt.Sprint(s.Ports.RPC), "OPS_V2_DEMO_ENGINE_PORT": fmt.Sprint(s.Ports.Engine), "OPS_V2_DEMO_OPS_PORT": fmt.Sprint(s.Ports.OPS), "OPS_V2_DEMO_EXPLORER_API_PORT": fmt.Sprint(s.Ports.ExplorerAPI), "OPS_V2_DEMO_EXPLORER_PORT": fmt.Sprint(s.Ports.Explorer), "OPS_V2_DEMO_WALLET_PORT": fmt.Sprint(s.Ports.Wallet), "OPS_V2_DEMO_INDEXER_PORT": fmt.Sprint(s.Ports.Indexer), "OPS_V2_DEMO_INDEXER_GRPC_PORT": fmt.Sprint(s.Ports.IndexerGRPC), "OPS_V2_DEMO_INDEXER_METRICS_PORT": fmt.Sprint(s.Ports.IndexerMetrics)})
}

func (s State) writeTail() error {
	var e error
	if _, e = writeBytes(s.file("urls.txt"), []byte("OPS: "+s.OPSOrigin()+"/login\nExplorer: "+s.ExplorerOrigin()+"\nDemo wallet: "+s.WalletOrigin()+"\nReal application RPC: "+s.RPCURL()+"\n")); e != nil {
		return e
	}
	if e = s.writePorts(); e != nil {
		return e
	}
	return s.writeEnv("private/postgres.env", map[string]string{"POSTGRES_PASSWORD": s.Secrets["DEMO_POSTGRES_PASSWORD"], "POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres"})
}
