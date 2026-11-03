package perfgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The mock node runs in its own process (the test binary re-executed with
// OPS_GATE2_MOCK_CONFIG) and its own GOMAXPROCS, so load-generator GC and
// scheduling stalls are not charged to OPS as node latency.

type mockProcessConfig struct {
	ChainID       uint64 `json:"chain_id"`
	DeploymentID  string `json:"deployment_id"`
	PrivateToken  string `json:"private_token"`
	BlockTimeNS   int64  `json:"block_time_ns"`
	FinalityLagNS int64  `json:"finality_lag_ns"`
	LatencyNS     int64  `json:"latency_ns"`
	MaxBlockTxs   int    `json:"max_block_txs"`
}

type mockReady struct {
	Public  string `json:"public"`
	Private string `json:"private"`
	Control string `json:"control"`
}

// MockProcess is a running mock-node subprocess.
type MockProcess struct {
	PublicURL, PrivateURL, ControlURL string
	PID                               int
	cmd                               *exec.Cmd
	stdin                             io.WriteCloser
	exited                            chan struct{}
	log                               *os.File
	client                            *http.Client
}

// StartMockProcess launches the mock with procs scheduler threads.
func StartMockProcess(ctx context.Context, cfg MockNodeConfig, dir string, procs int) (*MockProcess, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(mockProcessConfig{ChainID: cfg.ChainID, DeploymentID: cfg.DeploymentID, PrivateToken: cfg.PrivateToken, BlockTimeNS: int64(cfg.BlockTime), FinalityLagNS: int64(cfg.FinalityLag), LatencyNS: int64(cfg.Latency), MaxBlockTxs: cfg.MaxBlockTxs})
	if err != nil {
		return nil, err
	}
	configPath, readyPath := filepath.Join(dir, "mock-config.json"), filepath.Join(dir, "mock-ready.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		return nil, err
	}
	_ = os.Remove(readyPath)
	log, err := os.Create(filepath.Join(dir, "mock-node.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMockNodeProcessMain$", "-test.timeout=0")
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(procs), "OPS_GATE2_MOCK_CONFIG="+configPath, "OPS_GATE2_MOCK_READY="+readyPath)
	cmd.Stdout, cmd.Stderr = log, log
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &MockProcess{PID: cmd.Process.Pid, cmd: cmd, stdin: stdin, exited: make(chan struct{}), log: log, client: &http.Client{Timeout: 5 * time.Minute}}
	go func() { _ = cmd.Wait(); close(p.exited) }()
	err = waitFor(ctx, 30*time.Second, func() bool {
		data, err := os.ReadFile(readyPath)
		if err != nil {
			return false
		}
		var ready mockReady
		if json.Unmarshal(data, &ready) != nil || ready.Control == "" {
			return false
		}
		p.PublicURL, p.PrivateURL, p.ControlURL = ready.Public, ready.Private, ready.Control
		return true
	})
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("mock node process did not start; see %s", log.Name())
	}
	return p, nil
}

// Close ends the subprocess (closing stdin makes it exit).
func (p *MockProcess) Close() {
	if p == nil || p.cmd == nil {
		return
	}
	_ = p.stdin.Close()
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
	p.log.Close()
}

// Index registers the pre-signed workload (hash, indexed sender, nonce).
func (p *MockProcess) Index(txs []Tx, senders []string) error {
	var body bytes.Buffer
	body.Grow(len(txs) * 60)
	for _, tx := range txs {
		hash, err := hex.DecodeString(strings.TrimPrefix(tx.Hash, "0x"))
		if err != nil || len(hash) != 32 {
			return fmt.Errorf("bad hash %q", tx.Hash)
		}
		sender, err := hex.DecodeString(strings.TrimPrefix(senders[tx.Sender], "0x"))
		if err != nil || len(sender) != 20 {
			return fmt.Errorf("bad sender %q", senders[tx.Sender])
		}
		body.Write(hash)
		body.Write(sender)
		_ = binary.Write(&body, binary.BigEndian, tx.Nonce)
	}
	resp, err := p.client.Post(p.ControlURL+"/control/index", "application/octet-stream", &body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("index: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Stats reads the mock's counters.
func (p *MockProcess) Stats() (MockStats, error) {
	var out MockStats
	resp, err := p.client.Get(p.ControlURL + "/control/stats")
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// Stamps streams the per-hash timeline.
func (p *MockProcess) Stamps() (map[string]Stamp, error) {
	resp, err := p.client.Get(p.ControlURL + "/control/stamps")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reader := bufio.NewReaderSize(resp.Body, 1<<20)
	out := map[string]Stamp{}
	record := make([]byte, 32+24)
	for {
		if _, err := io.ReadFull(reader, record); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		out["0x"+hex.EncodeToString(record[:32])] = Stamp{Arrived: int64(binary.BigEndian.Uint64(record[32:])), Replied: int64(binary.BigEndian.Uint64(record[40:])), Finalized: int64(binary.BigEndian.Uint64(record[48:]))}
	}
}

// ServeMockProcess is the subprocess body: it serves until stdin closes.
func ServeMockProcess(configPath, readyPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var c mockProcessConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	node := NewMockNode(MockNodeConfig{ChainID: c.ChainID, DeploymentID: c.DeploymentID, PrivateToken: c.PrivateToken, BlockTime: time.Duration(c.BlockTimeNS), FinalityLag: time.Duration(c.FinalityLagNS), Latency: time.Duration(c.LatencyNS), MaxBlockTxs: c.MaxBlockTxs})
	control := http.NewServeMux()
	control.HandleFunc("/control/index", func(w http.ResponseWriter, r *http.Request) {
		reader := bufio.NewReaderSize(r.Body, 1<<20)
		record := make([]byte, 60)
		for {
			if _, err := io.ReadFull(reader, record); err == io.EOF {
				break
			} else if err != nil {
				http.Error(w, "bad index", http.StatusBadRequest)
				return
			}
			node.Index("0x"+hex.EncodeToString(record[:32]), "0x"+hex.EncodeToString(record[32:52]), binary.BigEndian.Uint64(record[52:]))
		}
		w.WriteHeader(http.StatusOK)
	})
	var publicConns, privateConns atomic.Int64
	control.HandleFunc("/control/stats", func(w http.ResponseWriter, _ *http.Request) {
		stats := node.Stats()
		stats.ConnectionsOpened = map[string]int64{"public": publicConns.Load(), "private": privateConns.Load()}
		_ = json.NewEncoder(w).Encode(stats)
	})
	control.HandleFunc("/control/stamps", func(w http.ResponseWriter, _ *http.Request) {
		out := bufio.NewWriterSize(w, 1<<20)
		record := make([]byte, 32+24)
		for hash, s := range node.Stamps() {
			raw, err := hex.DecodeString(strings.TrimPrefix(hash, "0x"))
			if err != nil || len(raw) != 32 {
				continue
			}
			copy(record, raw)
			binary.BigEndian.PutUint64(record[32:], uint64(s.Arrived))
			binary.BigEndian.PutUint64(record[40:], uint64(s.Replied))
			binary.BigEndian.PutUint64(record[48:], uint64(s.Finalized))
			_, _ = out.Write(record)
		}
		_ = out.Flush()
	})
	ready := mockReady{}
	for _, target := range []struct {
		url     *string
		handler http.Handler
		conns   *atomic.Int64
	}{{&ready.Public, node.Public(), &publicConns}, {&ready.Private, node.Private(), &privateConns}, {&ready.Control, control, nil}} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		*target.url = "http://" + l.Addr().String()
		server := &http.Server{Handler: target.handler, ReadHeaderTimeout: 5 * time.Second}
		if counter := target.conns; counter != nil {
			server.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					counter.Add(1)
				}
			}
		}
		go func() { _ = server.Serve(l) }()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	encoded, _ := json.Marshal(ready)
	if err := os.WriteFile(readyPath+".tmp", encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(readyPath+".tmp", readyPath); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, os.Stdin) // parent closed stdin or exited
	return nil
}
