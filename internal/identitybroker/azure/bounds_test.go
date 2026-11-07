package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestProviderTransportBoundsBeforeSDKAndDoesNotFollowCallerEndpoints(t *testing.T) {
	uri := "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
	calls := 0
	body := `{"access_token":"x"}`
	client, owned := newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}, nil
	}), []string{"https://login.microsoftonline.com/tenant/v2.0"})
	if owned != nil {
		t.Fatal("test transport unexpectedly owned")
	}
	for _, target := range []string{"https://other.test/token", "http://login.microsoftonline.com/tenant/oauth2/v2.0/token", uri + "?next=evil", uri + "#fragment", "https://login.microsoftonline.com/common/oauth2/v2.0/token"} {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", target, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			t.Fatal("unapproved endpoint reached")
		}
	}
	if calls != 0 {
		t.Fatal("unapproved target reached inner transport")
	}
	for _, raw := range []string{strings.Repeat(" ", (256<<10)+1), `{"access_token":"x","access_token":"y"}`, `{"Access_Token":"x"}`, `{"id_token":null}`, `{"id_token":""}`, `{} {}`} {
		body = raw
		req, _ := http.NewRequestWithContext(context.Background(), "POST", uri, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			t.Fatal("unbounded/ambiguous response reached SDK")
		}
	}
	body = `{"access_token":"x","refresh_token":"y","token_type":"Bearer"}`
	req, _ := http.NewRequest("POST", uri, nil)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}
func TestProviderClaimParserBoundsNumbersAndFactSource(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key"}`))
	compact := func(payload string) string {
		return header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".AA"
	}
	for _, raw := range []string{compact(`{"iat":1,"iat":2}`), compact(`{"IAT":1}`), compact(`{"value":` + strings.Repeat("[", 10) + `0` + strings.Repeat("]", 10) + `}`), strings.Repeat("x", MaxCompactTokenBytes+1)} {
		if _, err := jwtObject(raw); err == nil {
			t.Fatal("ambiguous/oversized provider JWT accepted")
		}
	}
	for _, raw := range []string{"-0", "1.0", "1e1", "9223372036854775807", "253402300800"} {
		if _, _, err := integer(map[string]any{"iat": json.Number(raw)}, "iat", true); err == nil {
			t.Fatal("noncanonical/out-of-range numeric date", raw)
		}
	}
	if _, _, err := times(map[string]any{"iat": json.Number("1"), "exp": json.Number("9223372036854775807")}, 1); err == nil {
		t.Fatal("SDK time overflow")
	}
	roles := identity.Profile{FactSource: "appRoles"}
	groups := identity.Profile{FactSource: "groupIds"}
	source := map[string]any{"roles": []any{"Reader"}, "hasgroups": true, "_claim_names": map[string]any{"groups": "source1"}}
	if facts, err := selectedFacts(source, roles); err != nil || len(facts) != 1 {
		t.Fatal("group overage erased independent app role", err)
	}
	if _, err := selectedFacts(source, groups); err == nil {
		t.Fatal("group overage accepted without actual groups")
	}
	if facts, err := selectedFacts(map[string]any{}, groups); err != nil || len(facts) != 0 {
		t.Fatal("missing group claim is not empty", err)
	}
	guid := "ABCDEFAB-1234-1234-1234-ABCDEFABCDEF"
	facts, err := selectedFacts(map[string]any{"groups": []any{guid}}, groups)
	if err != nil || facts[0].Value != strings.ToLower(guid) {
		t.Fatal("noncanonical external group identity", err)
	}
	if _, err := selectedFacts(map[string]any{"groups": []any{guid, strings.ToLower(guid)}}, groups); err == nil {
		t.Fatal("canonical duplicate group accepted")
	}
	if _, err := selectedFacts(map[string]any{"roles": []any{"Reader", "reader"}}, roles); err != nil {
		t.Fatal("case-sensitive distinct app roles collapsed")
	}
}
