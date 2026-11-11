package admissionsql_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	log "privacy-proxy/internal/activitylog"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	h "privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
)

func historyShare(t *testing.T, scope a.Scope, recipient string) a.Share {
	t.Helper()
	actors, digest, err := a.NormalizeRecipients([]string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	return a.Share{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, Recipients: actors, RecipientDigest: digest, DeclaredAt: time.Unix(f.Now, 0).UTC(), Witness: a.Witness{AnchorHash: common.Hash{1}, AnchorNumber: 1, AnchorTimestamp: uint64(f.Now), ManifestDigest: a.Digest{2}, WalletVersion: a.Digest{3}, WalletEvidenceAt: time.Unix(f.Now, 0).UTC()}}
}
func putHistoryShare(t *testing.T, store *admissionsql.Store, scope a.Scope, share a.Share) {
	t.Helper()
	receipt, err := store.WithRawTransaction(t.Context(), scope, func(tx a.RawTx) (a.CommitKind, error) { return a.CommitAllow, tx.PutShare(share) })
	if err != nil || !receipt.Committed {
		t.Fatal("actual immutable share writer", err)
	}
}

func TestHistorySharesActualReaderCurrentWalletAndPublicationFence(t *testing.T) {
	d := setupObserver(t)
	binding, scope := creationScope(t, d.db)
	network := networkidentity.Binding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
	expected := h.ShareBinding{Network: network, State: scope.State, SchemaProfile: h.ShareSchemaProfile}
	if wrong, err := admissionsql.OpenReader(t.Context(), d.db.appDSN); err == nil {
		wrong.Close()
		t.Fatal("writer DSN accepted as reader")
	}
	store, err := admissionsql.OpenReader(t.Context(), d.db.readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader, err := admissionsql.NewShareReader(store, expected)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []*admissionsql.Store{d.app, d.observer, d.facts, nil} {
		if _, err := admissionsql.NewShareReader(wrong, expected); err == nil {
			t.Fatal("non-reader mode accepted")
		}
	}
	share := historyShare(t, scope, f.Actor(f.Subject))
	putHistoryShare(t, d.app, scope, share)
	missing := common.Hash{9}
	pass, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash, missing}})
	if err != nil {
		t.Fatal("actual bounded known-commit read", err)
	}
	if actual, ok := pass.Share(scope.Hash); !ok || !actual.SameBinding(share) {
		t.Fatal("actual immutable share not preserved")
	}
	if _, ok := pass.Share(missing); ok {
		t.Fatal("missing was positive")
	}
	if reader.Recheck(t.Context(), pass) != nil {
		t.Fatal("same positive source")
	}
	second, err := admissionsql.NewShareReader(store, expected)
	if err != nil {
		t.Fatal(err)
	}
	if second.Recheck(t.Context(), pass) == nil {
		t.Fatal("another actual reader accepted original pass")
	}
	lateScope := scope
	lateScope.Hash = missing
	late := historyShare(t, lateScope, f.Actor(f.Subject))
	putHistoryShare(t, d.app, lateScope, late)
	if reader.Recheck(t.Context(), pass) != nil {
		t.Fatal("new absent listing should await next request")
	}
	if _, ok := pass.Share(missing); ok {
		t.Fatal("late listing widened original pass")
	}
	for _, change := range []func(*h.ShareBinding){func(b *h.ShareBinding) { b.State.Generation = uuid.NewString() }, func(b *h.ShareBinding) { b.State.Coverage[0] ^= 1 }, func(b *h.ShareBinding) { b.Network.DeploymentID = "foreign" }} {
		wrong := expected
		change(&wrong)
		stale, err := admissionsql.NewShareReader(store, wrong)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stale.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err == nil {
			t.Fatal("wrong network/generation/coverage read")
		}
	}
	t.Run("malformed_present_rows_never_absent", func(t *testing.T) {
		for _, column := range []string{"recipient_digest", "manifest_digest", "wallet_version"} {
			if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET `+column+`=$3 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err == nil {
				t.Fatal("malformed positive accepted", column)
			}
			var original []byte
			switch column {
			case "recipient_digest":
				original = share.RecipientDigest[:]
			case "manifest_digest":
				original = share.Witness.ManifestDigest[:]
			case "wallet_version":
				original = share.Witness.WalletVersion[:]
			}
			if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET `+column+`=$3 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], original); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET anchor_number=1.5 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.Read(t.Context(), h.ShareQuery{Hashes: []common.Hash{scope.Hash}}); err == nil {
			t.Fatal("fractional anchor silently narrowed")
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET anchor_number=1 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]); err != nil {
			t.Fatal(err)
		}
		// SQL's regexp permits noncanonical final base64 bits; actual ActorID
		// validation and recipient digest checking still reject that row.
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET recipients=ARRAY[$3] WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], "ops:p1:"+strings.Repeat("A", 42)+"B"); err != nil {
			t.Fatal(err)
		}
		if reader.Recheck(t.Context(), pass) == nil {
			t.Fatal("malformed replacement became absent")
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET recipients=$3 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:], share.Recipients); err != nil {
			t.Fatal(err)
		}
	})

	var clock atomic.Int64
	clock.Store(f.Now)
	snapshot := f.StateSnapshot(t, f.DefaultStateFixture(t))
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	wallet := f.ActualWalletFixture(t, t.Context(), d.db.ownerDSN, snapshot, network, func() time.Time { return time.Unix(clock.Load(), 0) })
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := wallet.Link(t, t.Context(), token, key)
	config := h.Config{Snapshot: snapshot, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }, Network: network, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, Shares: reader, ShareExpected: expected}
	factory, err := h.New(config)
	if err != nil {
		t.Fatal(err)
	}
	current, err := factory.Begin(t.Context(), token, f.Org, "eth_getCode")
	if err != nil {
		t.Fatal(err)
	}
	current, err = current.WithShares(t.Context(), []common.Hash{scope.Hash})
	if err != nil || !current.Listed(scope.Hash) {
		t.Fatal("actual actor listing", err)
	}
	if current.Recheck(t.Context()) != nil {
		t.Fatal("temporary SQL child lost original fence")
	}
	if _, err := wallet.Service.Unlink(t.Context(), token, address.Hex()); err != nil {
		t.Fatal(err)
	}
	if current.Recheck(t.Context()) == nil {
		t.Fatal("actual unlink not noticed")
	}

	recorder, _, _ := currentAddressActualRecorder(t, d, network, &clock, []string{"eth_getCode"})
	// A finite test-only HTTP assembly demonstrates the source helper's exact
	// required placement. It is not the yet-to-be-built H1 history dispatcher.
	for _, mode := range []string{"unchanged", "unlink-after-append", "share-changed-after-append", "wallet-reassigned", "unlink-during-share-SQL", "expiry-during-share-SQL"} {
		t.Run(mode, func(t *testing.T) {
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			address := wallet.Link(t, t.Context(), token, key)
			appended := make(chan struct{})
			release := make(chan struct{})
			gateError := make(chan error, 1)
			front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := factory.Begin(r.Context(), token, f.Org, "eth_getCode")
				if err == nil {
					c, err = c.WithShares(r.Context(), []common.Hash{scope.Hash})
				}
				if err != nil {
					gateError <- err
					http.Error(w, "unavailable", 503)
					return
				}
				slot, err := recorder.Reserve()
				if err == nil {
					_, err = slot.Complete(log.Completion{ActorID: c.OriginalView().ActorID(), DataOrganizationID: f.Org, Method: "eth_getCode", HTTPStatus: 200, Outcome: log.Success, PolicyDigest: log.Digest{1}})
				}
				if err != nil {
					gateError <- err
					http.Error(w, "unavailable", 503)
					return
				}
				close(appended)
				<-release
				err = c.Recheck(r.Context())
				gateError <- err
				if err != nil {
					http.Error(w, "unavailable", 503)
					return
				}
				_, _ = io.WriteString(w, "protected-history-fixture")
			}))
			defer front.Close()
			type answer struct {
				status int
				body   []byte
				err    error
			}
			done := make(chan answer, 1)
			go func() {
				response, err := front.Client().Get(front.URL)
				if err != nil {
					done <- answer{err: err}
					return
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				done <- answer{response.StatusCode, body, err}
			}()
			select {
			case <-appended:
			case err := <-gateError:
				t.Fatal("before actual Append", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Append timeout")
			}
			var restore func()
			switch mode {
			case "unlink-after-append", "wallet-reassigned":
				if _, err := wallet.Service.Unlink(t.Context(), token, address.Hex()); err != nil {
					t.Fatal(err)
				}
				if mode == "wallet-reassigned" {
					otherToken := f.Token(t, snapshot, f.AdminSubject, "Auditor")
					wallet.Link(t, t.Context(), otherToken, key)
					other, err := factory.Begin(t.Context(), otherToken, f.Org, "eth_getCode")
					if err != nil {
						t.Fatal(err)
					}
					other, err = other.WithShares(t.Context(), []common.Hash{scope.Hash})
					if err != nil || other.Listed(scope.Hash) {
						t.Fatal("wallet reassignment inherited immutable listing", err)
					}
				}
			case "share-changed-after-append":
				if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET anchor_timestamp=anchor_timestamp+1 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.tx_shares SET anchor_timestamp=anchor_timestamp-1 WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "expiry-during-share-SQL" || mode == "unlink-during-share-SQL" {
				lock, err := d.db.owner.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Rollback(context.Background())
				if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_admission_v2.tx_shares IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				close(release)
				deadline := time.Now().Add(500 * time.Millisecond)
				for {
					var waiting bool
					if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='admission_reader' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("actual share SQL did not wait")
					}
					time.Sleep(time.Millisecond)
				}
				if mode == "expiry-during-share-SQL" {
					clock.Store(f.Now + 300)
				} else {
					if _, err := wallet.Service.Unlink(t.Context(), token, address.Hex()); err != nil {
						t.Fatal(err)
					}
				}
				if err := lock.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				close(release)
			}
			response := <-done
			if response.err != nil {
				t.Fatal(response.err)
			}
			err = <-gateError
			positive := mode == "unchanged"
			if positive {
				if err != nil || response.status != 200 || string(response.body) != "protected-history-fixture" {
					t.Fatal("actual unchanged publication", response.status, err)
				}
			} else if err == nil || response.status != 503 || bytes.Contains(response.body, []byte("protected-history-fixture")) {
				t.Fatal("protected bytes after actual Append/source change", response.status, err)
			}
			if restore != nil {
				restore()
			}
			clock.Store(f.Now)
		})
	}
	if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.network_state SET generation=$2::uuid WHERE network_key=$1`, scope.Network[:], uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if reader.Recheck(t.Context(), pass) == nil {
		t.Fatal("stale original source generation accepted")
	}
}
