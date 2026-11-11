package identitysql_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/ssohttp"
	"strings"
	"testing"
	"time"
)

func TestE1SSOAndAuthShareEightSlots(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{d.Org}, false)
	view, client, _ := ssorelayHandler(t, s)
	var releases []func()
	for range 8 {
		release, ok := x.serviceOne.TryAdmitHTTP()
		if !ok {
			t.Fatal("normal eight-slot bound")
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	status, _, _ := view.request(t, client, "POST", ssohttp.Prefix+"token", "", func(r *http.Request) { r.Header.Del("Origin") })
	if status != 503 {
		t.Fatal("SSO bypassed shared gate", status)
	}
	authView := &browserFixture{db: x.db, origin: x.origin, first: x.first, second: x.first}
	authClient := authView.newClient(t, false)
	status, _, _ = authView.request(t, authClient, "GET", identityhttp.Prefix+"providers", nil, nil)
	if status != 503 {
		t.Fatal("auth handler has a separate gate", status)
	}
	releases[0]()
	status, _, _ = view.request(t, client, "POST", ssohttp.Prefix+"token", "", func(r *http.Request) { r.Header.Del("Origin") })
	if status != 401 {
		t.Fatal("released shared slot unavailable", status)
	}
}
func TestE1ActualSocketBodyDeadline(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{d.Org}, false)
	h, e := ssohttp.New(s.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 150*time.Millisecond)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
		done <- struct{}{}
	}))
	defer server.Close()
	connection, e := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, e = fmt.Fprintf(connection, "POST /api/v2/sso/flow HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", strings.TrimPrefix(x.origin, "https://"), x.origin)
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("body read outlived earlier parent socket deadline")
	}
	_, _ = io.Copy(io.Discard, connection)
	var releases []func()
	for range 8 {
		release, ok := x.serviceOne.TryAdmitHTTP()
		if !ok {
			t.Fatal("stalled body retained admission slot")
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		release()
	}
}

type ssoDelayedOutput struct {
	http.ResponseWriter
	ctx     context.Context
	entered chan<- struct{}
}

func (w *ssoDelayedOutput) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *ssoDelayedOutput) Write(raw []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.ctx.Done()
	n, e := w.ResponseWriter.Write(raw)
	if e == nil {
		e = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, e
}
func TestE1AdmissionHeldThroughDelayedActualOutput(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{d.Org}, false)
	h, e := ssohttp.New(s.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	entered, done := make(chan struct{}, 1), make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 400*time.Millisecond)
		defer cancel()
		h.ServeHTTP(&ssoDelayedOutput{ResponseWriter: w, ctx: ctx, entered: entered}, r.WithContext(ctx))
		done <- struct{}{}
	}))
	defer server.Close()
	result := make(chan error, 1)
	go func() {
		request, e := http.NewRequest("POST", server.URL+ssohttp.Prefix+"token", nil)
		if e != nil {
			result <- e
			return
		}
		request.Host = strings.TrimPrefix(x.origin, "https://")
		response, e := server.Client().Do(request)
		if e == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		result <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual output not reached")
	}
	var releases []func()
	for range 7 {
		release, ok := x.serviceOne.TryAdmitHTTP()
		if !ok {
			t.Fatal("expected seven remaining slots")
		}
		releases = append(releases, release)
	}
	if release, ok := x.serviceOne.TryAdmitHTTP(); ok {
		release()
		t.Fatal("slot released before writer completion")
	}
	for _, release := range releases {
		release()
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("output outlived earlier write deadline")
	}
	<-result
	release, ok := x.serviceOne.TryAdmitHTTP()
	if !ok {
		t.Fatal("completed output retained slot")
	}
	release()
}
