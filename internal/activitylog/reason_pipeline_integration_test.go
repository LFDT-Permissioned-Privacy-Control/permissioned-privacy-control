package activitylog_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/accesslog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

// These reasons originate in actual native authorization branches. They cross
// restricted wallet SQL, HTTP, synchronous local append, the SQL guard/sealer
// and the admin-only reader; no test constructs the recorded completion.
func TestReasonActualNativeHTTPRecorderAndAdminRoundTrip(t *testing.T) {
	db := rawPostgres(t)
	if _, err := db.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now)
	f := metadataFixture()
	f.clock = &clock
	f.groups[0].IsOrgReadonlyAdmin = true
	f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "blocked", Name: "Blocked", AllowedMethods: []string{"eth_getCode"}, Claims: []string{}})
	f.bindings[0].Allow = []policycore.FrameRule{{StorageAddress: addressA, Selector: "*"}}
	n := &node{}
	engine, accessToken, financial, snapshot := mountedRawEngine(t, f, n, db, false)
	blockedToken := token(t, snapshot, []string{second})
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	x := setupActivityDatabase(t, network)
	recorder := rpcRecorder(t, x, fixtureServingClock(f), nil, activitymethoddata.AdminAccessLogs)
	service, err := rpcactivity.New(rpcactivity.Config{Snapshot: snapshot, Clock: fixtureServingClock(f), Engine: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Handler(orgA)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	for _, test := range []struct {
		method, call, bearer string
		reason               activityreasondata.Code
	}{
		{"eth_call", `{"to":"` + addressA + `","data":"0x01020304"}`, blockedToken, activityreasondata.MethodNotAllowed},
		{"eth_call", `{"to":"` + addressA + `","from":"` + walletAddress + `","data":"0x01020304"}`, accessToken, activityreasondata.SenderNotLinked},
		{"eth_call", `{"to":"` + addressC + `","data":"0x01020304"}`, accessToken, activityreasondata.PolicyNoMatchingRule},
	} {
		t.Run(string(test.reason), func(t *testing.T) {
			before := metadataRows(t, x)
			body := `{"jsonrpc":"2.0","id":1,"method":"` + test.method + `","params":[` + test.call + `]}`
			wire := bodyResult(t, requestAsync(t, front.Client(), front.URL, test.bearer, body, t.Context()))
			if !bytes.Contains(wire, []byte(`"code":-32001`)) || bytes.Contains(wire, []byte(test.reason)) {
				t.Fatal("ordinary caller response changed or exposes admin reason", string(wire))
			}
			sealed := metadataSealedOne(t, x, before)
			if sealed.Version != 2 || sealed.Reason != test.reason || sealed.Outcome != "denied" || sealed.DataOrg != orgA || sealed.ActorID == "" {
				t.Fatal("actual selected branch reason lost or changed before sealing", sealed)
			}
		})
	}
	reader, err := s.OpenReader(t.Context(), x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	admin, err := accesslog.New(accesslog.Config{Snapshot: snapshot, Reader: activitysource.AdminReader{Store: reader}, Expected: reader.Metadata(), Clock: fixtureServingClock(f), Keys: accesslog.Keys{Active: accesslog.Key{ID: "admin", Bytes: bytes.Repeat([]byte{17}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	adminHandler, err := accesslog.NewHandler(admin, recorder)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	adminHandler.Register(mux)
	adminFront := httptest.NewTLSServer(mux)
	defer adminFront.Close()
	q := url.Values{"from": {time.Unix(now-1, 0).UTC().Format(time.RFC3339Nano)}, "to": {time.Unix(now+1, 0).UTC().Format(time.RFC3339Nano)}, "outcome": {"denied"}, "limit": {"25"}}
	read := func(org, bearer string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), "GET", adminFront.URL+"/api/v2/orgs/"+org+"/access-logs?"+q.Encode(), nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := adminFront.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 193<<10))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	status, body := read(orgA, accessToken)
	var page accesslog.Page
	if status != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) != 3 {
		t.Fatal("scoped admin did not receive recorded actual reasons", status, string(body))
	}
	seen := map[string]bool{}
	for _, item := range page.Items {
		seen[item.Reason] = true
	}
	for _, reason := range []activityreasondata.Code{activityreasondata.MethodNotAllowed, activityreasondata.SenderNotLinked, activityreasondata.PolicyNoMatchingRule} {
		if !seen[string(reason)] {
			t.Fatal("admin reason missing", reason, string(body))
		}
	}
	for _, test := range []struct{ org, bearer string }{{orgA, ""}, {orgB, accessToken}} {
		status, body := read(test.org, test.bearer)
		if status < 400 || strings.Contains(string(body), string(activityreasondata.SenderNotLinked)) {
			t.Fatal("admin reasons escaped authentication/organization scope", status, string(body))
		}
	}
}
