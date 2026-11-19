// Command v2-network-probe is test infrastructure. The production image does
// not contain it. A test copies it into a running service namespace to check
// actual numeric-IP connectivity without adding tools to runtime images.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
)

func main() {
	mode := flag.String("mode", "tcp", "tcp, grpc, http or https")
	target := flag.String("target", "", "numeric IP and port")
	publicHost := flag.String("host", "", "expected HTTP authority")
	caFile := flag.String("ca", "/demo/ca.crt", "owned CA for HTTPS readiness")
	flag.Parse()
	host, _, err := net.SplitHostPort(*target)
	if err != nil || net.ParseIP(host) == nil || flag.NArg() != 0 || (*mode != "tcp" && *mode != "grpc" && *mode != "http" && *mode != "https") {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := struct {
		TCPConnected bool `json:"tcpConnected"`
		GRPCHealthy  bool `json:"grpcHealthy"`
		HTTPHealthy  bool `json:"httpHealthy"`
	}{}
	socket, err := (&net.Dialer{}).DialContext(ctx, "tcp", *target)
	if err == nil {
		result.TCPConnected = true
		_ = socket.Close()
	}
	if result.TCPConnected && *mode == "grpc" {
		client, e := grpc.NewClient(*target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)))
		if e == nil {
			defer client.Close()
			view, e := pb.NewIndexerServiceClient(client).GetChainView(ctx, &pb.GetChainViewRequest{})
			result.GRPCHealthy = e == nil && view.GetPage().GetDatasetEpoch() != "" && len(view.GetPage().GetReadAt().GetBlockHash()) == 32 && len(view.GetGenesisHash()) == 32
		}
	}
	if result.TCPConnected && (*mode == "http" || *mode == "https") {
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		if *mode == "https" {
			ca, err := os.ReadFile(*caFile)
			if err != nil {
				os.Exit(2)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				os.Exit(2)
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, *mode+"://"+*target+"/health/ready", nil)
		if err == nil {
			req.Host = *publicHost
			response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
			if err == nil {
				result.HTTPHealthy = response.StatusCode >= 200 && response.StatusCode < 300
				response.Body.Close()
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
	if !result.TCPConnected || (*mode == "grpc" && !result.GRPCHealthy) || ((*mode == "http" || *mode == "https") && !result.HTTPHealthy) {
		os.Exit(1)
	}
}
