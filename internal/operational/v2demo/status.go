package v2demo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/operational/admissionsql"
)

type StatusResult struct {
	Configured    bool    `json:"configured"`
	OPSReady      bool    `json:"opsReady"`
	WalletReady   bool    `json:"walletReady"`
	ExplorerReady bool    `json:"explorerReady"`
	IndexedBlock  *int64  `json:"indexedBlock"`
	ObserverReady bool    `json:"observerReady"`
	CaptureReady  bool    `json:"captureReady"`
	ObserverHead  *uint64 `json:"observerHead"`
	Ready         bool    `json:"ready"`
}

func Status(parent context.Context, root string) (StatusResult, error) {
	var result StatusResult
	root, e := canonicalRoot(root)
	if e != nil {
		return result, e
	}
	s, e := readState(root)
	if e != nil {
		return result, e
	}
	result.Configured = s.Configured
	if !s.Configured {
		return result, nil
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	ca, e := os.ReadFile(s.file("ca.crt"))
	if e != nil {
		return result, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return result, ErrInvalid
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(url string, target any) int {
		q, e := http.NewRequestWithContext(ctx, "GET", url, nil)
		if e != nil {
			return 0
		}
		r, e := client.Do(q)
		if e != nil {
			return 0
		}
		defer r.Body.Close()
		if target != nil {
			if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(target) != nil {
				return 0
			}
		}
		return r.StatusCode
	}
	result.OPSReady = get(s.OPSOrigin()+"/health/ready", nil) == 204
	var wallet struct{ Ready, TestOnly bool }
	result.WalletReady = get(s.WalletOrigin()+"/health", &wallet) == 200 && wallet.Ready && wallet.TestOnly
	var app struct {
		Protocol      string `json:"protocol"`
		Authenticated bool   `json:"authenticated"`
	}
	result.ExplorerReady = get(s.ExplorerOrigin()+"/api/auth/status", &app) == 200 && app.Protocol == "ops-v2" && !app.Authenticated
	if c, e := pgx.Connect(ctx, s.dsn("index", "postgres")); e == nil {
		var height int64
		if c.QueryRow(ctx, `SELECT last_indexed_block FROM public.sync_status ORDER BY id LIMIT 1`).Scan(&height) == nil {
			result.IndexedBlock = &height
		}
		c.Close(ctx)
	}
	binding := admission.NetworkBinding{Environment: Environment, ChainID: ChainID, GenesisHash: s.GenesisHash, DeploymentID: Deployment}
	if status, e := admissionsql.CreationObserverStatus(ctx, s.dsn("admission", "postgres"), binding); e == nil {
		result.ObserverReady = status.Ready && status.LeaseRemainingTTL > 0
		result.CaptureReady = status.CaptureReady
		head := status.Head.Number
		result.ObserverHead = &head
	}
	result.Ready = result.OPSReady && result.WalletReady && result.ExplorerReady && result.IndexedBlock != nil && result.ObserverReady && result.CaptureReady
	return result, nil
}
func Wait(parent context.Context, root string) error {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		status, e := Status(ctx, root)
		if e != nil {
			return e
		}
		if status.Ready {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return ErrInvalid
}
