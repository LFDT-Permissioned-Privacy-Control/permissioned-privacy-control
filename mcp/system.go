package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSystemTools(s *mcp.Server, client *httpClient) {
	registerHealth(s, client)
	registerStatus(s, client)
	registerTestRequest(s, client)
	registerEthAddressCollisions(s, client)
}

func registerHealth(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "health",
		Description: "Check if the Open Privacy Suite is reachable.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/health")
		if err != nil {
			return errorResult("Open Privacy Suite unreachable: %v\n\nIs it running? Try: docker-compose up -d", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(
			section("Open Privacy Suite Health: OK"),
			kvf("Status", getString(m, "status")),
		)
	})
}

func registerStatus(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "status",
		Description: "Get Open Privacy Suite status: proxy state, node connectivity, and security config.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/status")
		if err != nil {
			return errorResult("Status failed: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return errorResult("Parsing status: %v", err)
		}

		lines := section("Open Privacy Suite Status") + "\n"

		if proxy := getMap(m, "proxy"); proxy != nil {
			lines += joinLines(
				kvf("Proxy Status", getString(proxy, "status")),
				kvf("Proxy Port", getString(proxy, "port")),
			) + "\n"
		}

		if node := getMap(m, "node"); node != nil {
			lines += joinLines(
				kvf("Node Status", getString(node, "status")),
				kvf("Node URL", getString(node, "url")),
				kvf("Node Latency", fmt.Sprintf("%dms", int64(getFloat(node, "latency_ms")))),
			) + "\n"
		}

		if sec := getMap(m, "security"); sec != nil {
			lines += kvf("Travel Rule", boolYesNo(getBool(sec, "travel_rule_enabled")))
		}

		return textResult(lines)
	})
}

type testRequestArgs struct {
	Method   string `json:"method" jsonschema:"JSON-RPC method to test (e.g. eth_call, required)"`
	Params   any    `json:"params,omitempty" jsonschema:"JSON-RPC params (array or object)"`
	JWTToken string `json:"jwt_token,omitempty" jsonschema:"user JWT to test as (identity is taken from the validated token; omitted = the synthetic test:dashboard identity)"`
	OrgID    string `json:"org_id,omitempty" jsonschema:"org context to test in (required for users that belong to several orgs when the request has no target contract)"`
}

func registerTestRequest(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "test_request",
		Description: "Send a test JSON-RPC request through the proxy pipeline to verify RBAC, compliance, and filtering. Pass jwt_token to test as a specific user — 'what would this user be allowed to do?'.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args testRequestArgs) (*mcp.CallToolResult, any, error) {
		if args.Method == "" {
			return errorResult("method is required")
		}
		body := map[string]any{"method": args.Method}
		if args.Params != nil {
			body["params"] = args.Params
		}
		if args.JWTToken != "" {
			body["jwt_token"] = args.JWTToken
		}
		if args.OrgID != "" {
			body["org_id"] = args.OrgID
		}
		raw, err := client.post("/api/v1/admin/test-request", body)
		if err != nil {
			return errorResult("test request failed: %v", err)
		}
		return textResult(section("Test Request Result"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerEthAddressCollisions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "eth_address_collisions",
		Description: "Check for ETH address collisions across users.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/eth-addresses/collisions")
		if err != nil {
			return errorResult("checking address collisions: %v", err)
		}
		return textResult(section("ETH Address Collisions"), prettyJSON(json.RawMessage(raw)))
	})
}
