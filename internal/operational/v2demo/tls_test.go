package v2demo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSRepairPreservesDemoAuthorityAndSupportsECDSAClients(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if e := Init(root); e != nil {
		t.Fatal(e)
	}
	s, e := readState(root)
	if e != nil || !compatibleTLS(s) {
		t.Fatal("new P-256 TLS set invalid", e)
	}
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile(s.file(name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	unchanged := map[string][]byte{}
	for _, name := range []string{"private/state.json", "runtime.json", "genesis.json", "private/engine.jwt", "ca.crt", "private/ca.key", "tls.crt", "tls.key"} {
		unchanged[name] = read(name)
	}
	if e = Init(root); e != nil {
		t.Fatal(e)
	}
	if e = RepairTLS(root); e != nil {
		t.Fatal(e)
	}
	for name, before := range unchanged {
		if !bytes.Equal(before, read(name)) {
			t.Fatal("normal restart rotated valid material", name)
		}
	}
	// Reproduce the original demo certificate algorithm, then repair TLS only.
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	leafPub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	caPrivate, _ := x509.MarshalPKCS8PrivateKey(caKey)
	leafPrivate, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	for name, value := range map[string]*pem.Block{"ca.crt": {Type: "CERTIFICATE", Bytes: caDER}, "tls.crt": {Type: "CERTIFICATE", Bytes: leafDER}, "private/ca.key": {Type: "PRIVATE KEY", Bytes: caPrivate}, "tls.key": {Type: "PRIVATE KEY", Bytes: leafPrivate}} {
		if _, e = writeBytes(s.file(name), pem.EncodeToMemory(value)); e != nil {
			t.Fatal(e)
		}
	}
	if compatibleTLS(s) {
		t.Fatal("legacy Ed25519 TLS treated as browser-compatible")
	}
	if e = RepairTLS(root); e != nil || !compatibleTLS(s) {
		t.Fatal("legacy TLS repair failed", e)
	}
	// A P-256 certificate alone cannot mark a partial repair as complete.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongDER, _ := x509.MarshalPKCS8PrivateKey(wrongKey)
	if _, e = writeBytes(s.file("tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER})); e != nil {
		t.Fatal(e)
	}
	if compatibleTLS(s) {
		t.Fatal("mismatched P-256 leaf key accepted")
	}
	if e = Init(root); e != nil || !compatibleTLS(s) {
		t.Fatal("interrupted TLS repair was not recovered", e)
	}
	for _, name := range []string{"private/state.json", "runtime.json", "genesis.json", "private/engine.jwt"} {
		if !bytes.Equal(unchanged[name], read(name)) {
			t.Fatal("TLS repair changed identity/epochs/ports/chain", name)
		}
	}
	pair, e := tls.LoadX509KeyPair(s.file("tls.crt"), s.file("tls.key"))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read("ca.crt")) {
		t.Fatal("missing repaired CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}}
	defer transport.CloseIdleConnections()
	response, e := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(server.URL)
	if e != nil {
		t.Fatal("ECDSA TLS1.2 client rejected repaired certificate", e)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("unexpected TLS response")
	}
}
