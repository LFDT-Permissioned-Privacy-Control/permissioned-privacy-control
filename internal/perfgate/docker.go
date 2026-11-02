package perfgate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Container is a disposable container this runner started and must remove.
type Container struct {
	ID   string
	Name string
	Port string
}

func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args[:min(len(args), 2)], " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Remove stops and deletes the container (it was started with --rm).
func (c *Container) Remove(ctx context.Context) {
	if c == nil || c.ID == "" {
		return
	}
	_, _ = docker(ctx, "rm", "-f", "-v", c.ID)
}

// Postgres is a disposable Postgres 15 instance with pg_stat_statements.
type Postgres struct {
	Container
	Password string
}

// PostgresSettings is the one fixed, recorded server configuration used by
// every run on both trees (defaults otherwise).
func PostgresSettings() []string {
	return []string{"-c", "shared_preload_libraries=pg_stat_statements", "-c", "pg_stat_statements.track=all",
		"-c", "max_connections=400", "-c", "track_io_timing=on", "-c", "track_wal_io_timing=on",
		"-c", "shared_buffers=512MB", "-c", "max_wal_size=1GB", "-c", "checkpoint_timeout=15min"}
}

// StartPostgres starts postgres:15-alpine on a docker-chosen loopback port.
func StartPostgres(ctx context.Context, name string) (*Postgres, error) {
	p := &Postgres{Password: randomHex(16)}
	args := append([]string{"run", "-d", "--rm", "--name", name, "--label", "perfgate=true", "--shm-size", "1g",
		"-e", "POSTGRES_PASSWORD=" + p.Password, "-p", "127.0.0.1::5432", "postgres:15-alpine"}, PostgresSettings()...)
	id, err := docker(ctx, args...)
	if err != nil {
		return nil, err
	}
	p.ID, p.Name = id, name
	if err := waitFor(ctx, 60*time.Second, func() bool {
		_, err := docker(ctx, "exec", id, "pg_isready", "-U", "postgres", "-h", "127.0.0.1")
		return err == nil
	}); err != nil {
		p.Remove(ctx)
		return nil, fmt.Errorf("postgres %s did not start", name)
	}
	mapped, err := docker(ctx, "port", id, "5432/tcp")
	if err != nil {
		p.Remove(ctx)
		return nil, err
	}
	p.Port = mapped[strings.LastIndex(mapped, ":")+1:]
	return p, nil
}

// DSN builds a loopback connection string.
func (p *Postgres) DSN(database, user, password string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", user, password, p.Port, database)
}

// Psql runs SQL as the superuser inside the container.
func (p *Postgres) Psql(ctx context.Context, database, sql string) (string, error) {
	return docker(ctx, "exec", p.ID, "psql", "-v", "ON_ERROR_STOP=1", "-qtA", "-U", "postgres", "-d", database, "-c", sql)
}

// CPUMicros is the container's cumulative CPU time (cgroup v2 usage_usec).
func (c *Container) CPUMicros(ctx context.Context) (uint64, error) {
	out, err := docker(ctx, "exec", c.ID, "cat", "/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, fmt.Errorf("usage_usec missing in cpu.stat")
}

// StartRedis starts a password-protected redis:7-alpine.
func StartRedis(ctx context.Context, name, password string) (*Container, error) {
	id, err := docker(ctx, "run", "-d", "--rm", "--name", name, "--label", "perfgate=true", "-p", "127.0.0.1::6379", "redis:7-alpine", "redis-server", "--requirepass", password, "--save", "", "--appendonly", "no")
	if err != nil {
		return nil, err
	}
	c := &Container{ID: id, Name: name}
	if err := waitFor(ctx, 30*time.Second, func() bool {
		out, err := docker(ctx, "exec", id, "redis-cli", "-a", password, "--no-auth-warning", "ping")
		return err == nil && out == "PONG"
	}); err != nil {
		c.Remove(ctx)
		return nil, fmt.Errorf("redis %s did not start", name)
	}
	mapped, err := docker(ctx, "port", id, "6379/tcp")
	if err != nil {
		c.Remove(ctx)
		return nil, err
	}
	c.Port = mapped[strings.LastIndex(mapped, ":")+1:]
	return c, nil
}

func waitFor(ctx context.Context, limit time.Duration, ready func() bool) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out after %s", limit)
}
