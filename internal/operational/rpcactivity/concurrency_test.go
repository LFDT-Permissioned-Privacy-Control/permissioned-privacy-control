package rpcactivity

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
)

func localActor(i int) string {
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%032d", i)))
}

func TestLocalConcurrencyActiveOnlyFairnessAndConcurrentRelease(t *testing.T) {
	l := newLocalConcurrency(256)
	for _, actor := range []string{"", localActor(1)} {
		releases := []func(){}
		for i := 0; i < 50; i++ {
			release, ok := l.tryAcquire(actor)
			if !ok {
				t.Fatal("early rejection", i)
			}
			releases = append(releases, release)
		}
		if _, ok := l.tryAcquire(actor); ok {
			t.Fatal("51st admitted")
		}
		other, ok := l.tryAcquire(localActor(2))
		if !ok {
			t.Fatal("one noisy principal blocked another")
		}
		other()
		var wg sync.WaitGroup
		for _, release := range releases {
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func(release func()) { defer wg.Done(); release() }(release)
			}
		}
		wg.Wait()
		if len(l.actors) != 0 || l.anonymous != 0 {
			t.Fatal("leaked active entry")
		}
	}
	for i := 0; i < 1000; i++ {
		release, ok := l.tryAcquire(localActor(i))
		if !ok {
			t.Fatal(i)
		}
		release()
	}
	if len(l.actors) != 0 {
		t.Fatal("idle identity retained")
	}
	bounded := newLocalConcurrency(2)
	a, _ := bounded.tryAcquire(localActor(1))
	b, _ := bounded.tryAcquire(localActor(2))
	if _, ok := bounded.tryAcquire(localActor(3)); ok {
		t.Fatal("active map ceiling exceeded")
	}
	a()
	b()
}

func fairnessService(t *testing.T) (*Service, string, *atomic.Int64) {
	t.Helper()
	snapshot := f.Snapshot(t, nil)
	var instant atomic.Int64
	instant.Store(f.Now)
	clock := func() time.Time { return time.Unix(instant.Load(), 0) }
	catalog, _ := snapshot.Identity()
	verifier, err := identity.NewVerifier(catalog, clock)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{verifier: verifier, fairness: newLocalConcurrency(256), slots: make(chan struct{}, 256)}, f.Token(t, snapshot, f.Subject, "Auditor"), &instant
}

func TestVerifiedActorOnlyAndAnonymousHeaderGrouping(t *testing.T) {
	s, token, clock := fairnessService(t)
	releases := []func(){}
	for i := 0; i < 50; i++ {
		release, ok := s.acquireFairness([]string{"Bearer " + token})
		if !ok {
			t.Fatal(i)
		}
		releases = append(releases, release)
	}
	if _, ok := s.acquireFairness([]string{"Bearer " + token}); ok {
		t.Fatal("verified51st admitted")
	}
	otherToken := f.Token(t, f.Snapshot(t, nil), f.AdminSubject, "Admin")
	otherRelease, otherOK := s.acquireFairness([]string{"Bearer " + otherToken})
	if !otherOK {
		t.Fatal("verified noisy actor blocked independent actor")
	}
	otherRelease()
	rotated := f.Token(t, f.Snapshot(t, nil), f.Subject, "Readonly")
	if _, ok := s.acquireFairness([]string{"Bearer " + rotated}); ok {
		t.Fatal("rotated claims created a second bucket for same actor")
	}
	for _, headers := range [][]string{nil, {""}, {"Bearer broken"}, {"Bearer " + token, "Bearer " + token}, {"Bearer  " + token}, {"Basic " + token}, {"Bearer " + token[:len(token)-1] + "!"}} {
		release, ok := s.acquireFairness(headers)
		if !ok {
			t.Fatal("invalid header charged victim", headers)
		}
		release()
	}
	clock.Store(f.Now + 300)
	release, ok := s.acquireFairness([]string{"Bearer " + token})
	if !ok {
		t.Fatal("expired token charged verified victim")
	}
	release()
	for _, release := range releases {
		release()
	}
	if len(s.fairness.actors) != 0 || s.fairness.anonymous != 0 {
		t.Fatal("release leak")
	}
	// Missing and invalid identities consume the same fixed anonymous bucket.
	for i := 0; i < 50; i++ {
		release, ok := s.acquireFairness(nil)
		if !ok {
			t.Fatal(i)
		}
		defer release()
	}
	if _, ok := s.acquireFairness([]string{"Bearer forged"}); ok {
		t.Fatal("invalid token invented another anonymous bucket")
	}
}

func TestLocalCapRejectsBeforeBodyRecorderAndEngineWithOriginalDeadline(t *testing.T) {
	for _, explorer := range []bool{false, true} {
		t.Run(fmt.Sprint(explorer), func(t *testing.T) {
			s, token, _ := fairnessService(t)
			for i := 0; i < 50; i++ {
				release, ok := s.acquireFairness([]string{"Bearer " + token})
				if !ok {
					t.Fatal(i)
				}
				defer release()
			}
			body := &countReader{}
			r := httptest.NewRequest("POST", "https://ops.test/rpc", body)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set(RequestReferenceHeader, "untrusted")
			until := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), until)
			defer cancel()
			r = r.WithContext(ctx)
			w := &deadlineWriter{t: t, header: make(http.Header), expected: until}
			w.Header().Set(RequestReferenceHeader, "stale")
			// Both recorder and engines are nil: any use before rejection panics.
			if explorer {
				s.serveExplorer(w, r, "")
			} else {
				s.serve(w, r, "")
			}
			if w.status != 429 || w.writes != 1 || body.reads != 0 || len(s.slots) != 0 || w.Header().Get(RequestReferenceHeader) != "" || !w.writeDeadline.Equal(until) {
				t.Fatal("rejection escaped finite admission boundary", w.status, body.reads)
			}
			if strings.Contains(string(w.body), "result") {
				t.Fatal("protected result")
			}
		})
	}
}
