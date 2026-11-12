// Package v2server is the SQL-linked operational V2 composition root. Pure
// policy/Core packages do not import it. It never migrates a store, writes
// configuration, creates users or delegates to the legacy server.
package v2server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"

	"privacy-proxy/internal/strictjson"
)

var ErrInvalid = errors.New("invalid pinned V2 serving configuration")

type File struct {
	Path   string `json:"path"`
	Digest string `json:"sha256"`
}
type Selection struct {
	Directory      string `json:"directory"`
	ManifestDigest string `json:"manifestDigest"`
	Environment    string `json:"environment"`
	ChainID        string `json:"chainId"`
}
type Broker struct {
	DeploymentID         string `json:"deploymentId"`
	RecoveryEpoch        string `json:"recoveryEpoch"`
	AppDSNEnv            string `json:"appDSNEnv"`
	ProofDSNEnv          string `json:"proofDSNEnv"`
	SigningPrivateKeyEnv string `json:"signingPrivateKeyEnv"`
}
type Wallet struct {
	AppDSNEnv      string `json:"appDSNEnv"`
	ServiceOrigin  string `json:"serviceOrigin"`
	DeploymentID   string `json:"deploymentId"`
	GenesisHash    string `json:"genesisHash"`
	Generation     string `json:"generation"`
	CoverageDigest string `json:"coverageDigest"`
}
type SSO struct {
	AppDSNEnv     string `json:"appDSNEnv"`
	RecoveryEpoch string `json:"recoveryEpoch"`
	Clients       File   `json:"clients"`
	Runtime       File   `json:"runtime"`
}
type Config struct {
	APIVersion             string    `json:"apiVersion"`
	Kind                   string    `json:"kind"`
	Listen                 string    `json:"listen"`
	TLSCertificateFile     string    `json:"tlsCertificateFile"`
	TLSPrivateKeyFile      string    `json:"tlsPrivateKeyFile"`
	WebDirectory           string    `json:"webDirectory"`
	ExplorerOrganizationID string    `json:"explorerOrganizationId,omitempty" optional:"true"`
	Core                   Selection `json:"core"`
	BrokerSelection        Selection `json:"brokerSelection"`
	Broker                 Broker    `json:"broker"`
	Wallet                 Wallet    `json:"wallet"`
	SSO                    SSO       `json:"sso"`
	Data                   Data      `json:"data"`
	Protected              Protected `json:"protected"`
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func digest(value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 71 || value[:7] != "sha256:" {
		return out, ErrInvalid
	}
	b, e := hex.DecodeString(value[7:])
	if e != nil || hex.EncodeToString(b) != value[7:] {
		return out, ErrInvalid
	}
	copy(out[:], b)
	return out, nil
}
func readFile(name string, max int64) ([]byte, error) {
	f, e := os.Open(name)
	if e != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() > max {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrInvalid
	}
	return b, nil
}
func readPinned(file File, max int64) ([]byte, error) {
	want, e := digest(file.Digest)
	if e != nil {
		return nil, e
	}
	b, e := readFile(file.Path, max)
	if e != nil || sha256.Sum256(b) != want {
		return nil, ErrInvalid
	}
	return b, nil
}

// ReadConfig pins deployment selection before any provider, SQL or listener is
// opened. This file contains references, never literal DSNs/private secrets.
func ReadConfig(path, expected string) (Config, error) {
	var c Config
	b, e := readPinned(File{path, expected}, 128<<10)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, 16)
	if e != nil {
		return c, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return c, ErrInvalid
	}
	if strictjson.ExactDecode(v, &c) != nil {
		return c, ErrInvalid
	}
	if c.APIVersion != "ops.server/v2" || c.Kind != "OperationalServer" || c.TLSCertificateFile == "" || c.TLSPrivateKeyFile == "" || c.WebDirectory == "" {
		return c, ErrInvalid
	}
	_, port, e := net.SplitHostPort(c.Listen)
	if e != nil || port == "" || port == "0" {
		return c, ErrInvalid
	}
	for _, ref := range []string{c.Broker.AppDSNEnv, c.Broker.ProofDSNEnv, c.Broker.SigningPrivateKeyEnv, c.Wallet.AppDSNEnv, c.SSO.AppDSNEnv} {
		if !envName.MatchString(ref) {
			return c, ErrInvalid
		}
	}
	return c, nil
}
