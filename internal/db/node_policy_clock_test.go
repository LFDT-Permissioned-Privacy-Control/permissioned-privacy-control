package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"privacy-proxy/internal/nodepolicy"
)

// RD-1411 (plan §5.1, §5.2, §5.6): the fact clock bumps once per transaction,
// only when a column the export reads changes, notifies the publisher at
// commit, and records the changed keys for the incremental export.

func policyVersion(t *testing.T, d *DB) int64 {
	t.Helper()
	var v int64
	if err := d.conn.QueryRow(`SELECT version FROM node_policy_clock WHERE singleton`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

var clockTestNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "clock-test"}

func fullExport(t *testing.T, d *DB) nodepolicy.Snapshot {
	t.Helper()
	s, err := d.ExportNodePolicySnapshot(context.Background(), clockTestNetwork, time.Unix(1_800_000_000, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClockBumpsOncePerTransactionWithoutOutbox(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	var outbox sql.NullString
	if err := d.conn.QueryRowContext(ctx, `SELECT to_regclass('node_policy_outbox')::text`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if outbox.Valid {
		t.Fatal("node_policy_outbox still exists; nothing reads it (plan §4.10)")
	}
	userID, _ := cacheGenFixtures(t, d, ctx)
	before := policyVersion(t, d)

	// Several fact tables in one transaction: one version.
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`UPDATE users SET banned=true WHERE id=$1`,
		`UPDATE users SET kyc=false WHERE id=$1`,
		`INSERT INTO eth_address_links(did,eth_address,link_type) SELECT external_id,'0x7777777777777777777777777777777777777777','system' FROM users WHERE id=$1`,
		`INSERT INTO access_policies(external_id,banned) SELECT external_id,true FROM users WHERE id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			t.Fatal(err)
		}
	}
	var inside int64
	if err := tx.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&inside); err != nil {
		t.Fatal(err)
	}
	if inside != before+1 {
		t.Fatalf("one transaction must produce one version: %d -> %d", before, inside)
	}
	if policyVersion(t, d) != before {
		t.Fatal("uncommitted version visible")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := policyVersion(t, d); got != before+1 {
		t.Fatalf("committed version %d, want %d", got, before+1)
	}

	// Two transactions on the same session each bump: the marker is local to
	// its transaction, not to the connection.
	conn, err := d.conn.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	before = policyVersion(t, d)
	for i := 0; i < 2; i++ {
		if _, err := conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID); err != nil {
			t.Fatal(err)
		}
	}
	if got := policyVersion(t, d); got != before+2 {
		t.Fatalf("two transactions on one session: %d -> %d", before, got)
	}

	// A session-level value of the marker (stale or forged) never suppresses
	// a later transaction's bump.
	before = policyVersion(t, d)
	if _, err := conn.ExecContext(ctx, `SELECT set_config('ops.node_policy_tx', txid_current()::text || ':1', false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SET ops.node_policy_tx = '999999999:1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if got := policyVersion(t, d); got != before+1 {
		t.Fatalf("session-level marker suppressed a bump: %d -> %d", before, got)
	}
	if _, err := conn.ExecContext(ctx, `RESET ops.node_policy_tx`); err != nil {
		t.Fatal(err)
	}

	// A rolled-back savepoint takes its bump with it; the next change bumps
	// once and its key is recorded once.
	before = policyVersion(t, d)
	tx, err = d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, q := range []string{`SAVEPOINT s1`, `UPDATE users SET banned=NOT banned WHERE id=$1`, `ROLLBACK TO SAVEPOINT s1`, `UPDATE users SET kyc=NOT kyc WHERE id=$1`} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{userID}
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := policyVersion(t, d); got != before+1 {
		t.Fatalf("savepoint rollback: %d -> %d", before, got)
	}
	var keys int
	if err := d.conn.QueryRowContext(ctx, `SELECT count(*) FROM node_policy_changes WHERE version=$1 AND entity='principal' AND resource_key=$2`, before+1, userID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 1 {
		t.Fatalf("changed principal recorded %d times", keys)
	}
}

func TestNodePolicyClockSerializesCommitOrder(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	first, _ := cacheGenFixtures(t, d, ctx)
	second, _ := cacheGenFixtures(t, d, ctx)
	before := policyVersion(t, d)
	a, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Rollback()
	if _, err := a.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, first); err != nil {
		t.Fatal(err)
	}
	b, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Rollback()
	if _, err := b.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, second); err == nil {
		t.Fatal("later transaction could allocate a version before earlier commit")
	}
	if err := b.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != before+1 {
		t.Fatal("failed concurrent update published a version")
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != before+2 {
		t.Fatal("successful retry did not follow prior commit")
	}
}

// notifications collects NOTIFY payloads on its own connection.
type notifications struct {
	conn *pgx.Conn
}

func listenFor(t *testing.T, d *DB, channels ...string) *notifications {
	t.Helper()
	ctx := context.Background()
	conn, err := d.connectPgxUTC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	for _, ch := range channels {
		if _, err := conn.Exec(ctx, "LISTEN "+ch); err != nil {
			t.Fatal(err)
		}
	}
	return &notifications{conn: conn}
}

// drain returns every notification that arrives within wait.
func (n *notifications) drain(t *testing.T, wait time.Duration) []*pgconn.Notification {
	t.Helper()
	var out []*pgconn.Notification
	for {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		got, err := n.conn.WaitForNotification(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || pgconn.Timeout(err) {
				return out
			}
			t.Fatal(err)
		}
		out = append(out, got)
	}
}

func TestNodePolicyChangeNotifiesOncePerTransaction(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	n := listenFor(t, d, "node_policy_changed")
	n.drain(t, 50*time.Millisecond)

	if err := d.WithTx(ctx, func(tx *Tx) error {
		for _, q := range []string{`UPDATE users SET banned=true WHERE id=$1`, `UPDATE users SET kyc=false WHERE id=$1`,
			`INSERT INTO eth_address_links(did,eth_address,link_type) SELECT external_id,'0x7777777777777777777777777777777777777777','system' FROM users WHERE id=$1`} {
			if _, err := tx.tx.ExecContext(ctx, q, userID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := n.drain(t, 300*time.Millisecond)
	if len(got) != 1 || got[0].Payload != strconv.FormatInt(policyVersion(t, d), 10) {
		t.Fatalf("want one notification carrying the new version, got %+v", got)
	}

	// Rolled back: nothing. A non-dependency update: nothing.
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET banned=false WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET note='operator note', metadata='{"m":1}', updated_at=now() WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if got := n.drain(t, 300*time.Millisecond); len(got) != 0 {
		t.Fatalf("unexpected notifications: %+v", got)
	}
}

func TestNodePolicyAckPrunesChangeLogAndNotifiesApplied(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	acked := uint64(policyVersion(t, d))
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET kyc=false WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	n := listenFor(t, d, "node_policy_applied")
	if err := d.AcknowledgeNodePolicy(ctx, "producer", nodepolicy.AppliedState{Version: acked, Digest: strings.Repeat("a", 64), ExpiresAt: 2000}); err != nil {
		t.Fatal(err)
	}
	got := n.drain(t, 300*time.Millisecond)
	if len(got) != 1 || got[0].Payload != strconv.FormatUint(acked, 10) {
		t.Fatalf("want one applied notification for %d, got %+v", acked, got)
	}
	var below, above int
	var floor uint64
	if err := d.conn.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE version<=$1), count(*) FILTER (WHERE version>$1) FROM node_policy_changes`, acked).Scan(&below, &above); err != nil {
		t.Fatal(err)
	}
	if err := d.conn.QueryRowContext(ctx, `SELECT version FROM node_policy_change_floor`).Scan(&floor); err != nil {
		t.Fatal(err)
	}
	if below != 0 || above == 0 || floor != acked {
		t.Fatalf("change log not pruned through the acknowledgement: below=%d above=%d floor=%d", below, above, floor)
	}
	// A rejected acknowledgement prunes nothing and notifies nothing.
	if err := d.AcknowledgeNodePolicy(ctx, "producer", nodepolicy.AppliedState{Version: acked + 100, Digest: strings.Repeat("a", 64), ExpiresAt: 2000}); err == nil {
		t.Fatal("future acknowledgement accepted")
	}
	if got := n.drain(t, 200*time.Millisecond); len(got) != 0 {
		t.Fatalf("rejected ack notified: %+v", got)
	}
	if err := d.conn.QueryRowContext(ctx, `SELECT count(*) FROM node_policy_changes WHERE version>$1`, acked).Scan(&above); err != nil || above == 0 {
		t.Fatalf("rejected ack pruned the change log: %d %v", above, err)
	}
}

// factFixture is one organisation with every kind of fact.
type factFixture struct {
	org, otherOrg, user, otherUser, did, otherDID string
	group, otherGroup, contract, grant            string
	contractAddress, prereg, shared, sanction     string
	link, membership, policy                      string
}

func newFactFixture(t *testing.T, d *DB) factFixture {
	t.Helper()
	ctx := context.Background()
	f := factFixture{group: uuid.NewString(), otherGroup: uuid.NewString(), contract: uuid.NewString(), grant: uuid.NewString(),
		contractAddress: "0x" + strings.Repeat("c1", 20), prereg: "0x" + strings.Repeat("d1", 20), shared: "0x" + strings.Repeat("e1", 20), sanction: uuid.NewString(), membership: uuid.NewString(), policy: uuid.NewString()}
	f.user, f.org = cacheGenFixtures(t, d, ctx)
	f.otherUser, f.otherOrg = cacheGenFixtures(t, d, ctx)
	if err := d.conn.QueryRowContext(ctx, `SELECT external_id FROM users WHERE id=$1`, f.user).Scan(&f.did); err != nil {
		t.Fatal(err)
	}
	if err := d.conn.QueryRowContext(ctx, `SELECT external_id FROM users WHERE id=$1`, f.otherUser).Scan(&f.otherDID); err != nil {
		t.Fatal(err)
	}
	bytecode := []byte("fixture-runtime")
	sum := sha256.Sum256(bytecode)
	policyDigest := strings.Repeat("ab", 32)
	for _, s := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO groups(id,org_id,slug,name,depth,path) VALUES($1::uuid,$2,'g-'||$1::text,'G '||$1::text,0,'g-'||$1::text)`, []any{f.group, f.org}},
		{`INSERT INTO groups(id,org_id,slug,name,depth,path) VALUES($1::uuid,$2,'g-'||$1::text,'G '||$1::text,0,'g-'||$1::text)`, []any{f.otherGroup, f.otherOrg}},
		{`INSERT INTO group_access(group_id,claims,allowed_methods) VALUES($1,ARRAY['deploy'],ARRAY['eth_sendRawTransaction'])`, []any{f.group}},
		{`INSERT INTO group_access(group_id,claims,allowed_methods) VALUES($1,ARRAY['upgrade'],ARRAY['eth_sendRawTransaction'])`, []any{f.otherGroup}},
		{`INSERT INTO user_memberships(id,user_id,group_id) VALUES($1,$2,$3)`, []any{f.membership, f.user, f.group}},
		{`INSERT INTO eth_address_links(did,eth_address,link_type) VALUES($1,'0x1111111111111111111111111111111111111111','system')`, []any{f.did}},
		{`INSERT INTO contracts(id,org_id,address,name) VALUES($1,$2,$3,'Fixture')`, []any{f.contract, f.org, f.contractAddress}},
		{`INSERT INTO contract_grants(id,group_id,contract_id) VALUES($1,$2,$3)`, []any{f.grant, f.group, f.contract}},
		{`INSERT INTO shared_infrastructure(address,name,codehash) VALUES($1,'Shared','0x'||repeat('0f',32))`, []any{f.shared}},
		{`INSERT INTO preregistered_addresses(org_id,address) VALUES($1,$2)`, []any{f.org, f.prereg}},
		{`INSERT INTO sanctioned_addresses(id,org_id,address,reason) VALUES($1,$2,'0x'||repeat('f1',20),'fixture')`, []any{f.sanction, f.org}},
		{`INSERT INTO execution_policy_revisions(id,org_id,revision,status,source,policy_digest,solidity_source,solidity_digest,runtime_bytecode,runtime_digest,compiler)
		  VALUES($1,$2,1,'active','policy',$3,'contract P {}',$3,$4,$5,'{}'::jsonb)`, []any{f.policy, f.org, policyDigest, bytecode, hex.EncodeToString(sum[:])}},
	} {
		if _, err := d.conn.ExecContext(ctx, s.q, s.args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, s.q)
		}
	}
	if err := d.conn.QueryRowContext(ctx, `SELECT id::text FROM eth_address_links WHERE did=$1`, f.did).Scan(&f.link); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestNodePolicyTriggerDependenciesMatchExport is the static half of G1. A
// role that may read ONLY the declared dependency columns runs the full and
// the incremental export: Postgres refuses any other column or table, so the
// export reads nothing outside the set. The UPDATE triggers fire on exactly
// that set, and every fact table also has its insert/delete and truncate
// triggers.
func TestNodePolicyTriggerDependenciesMatchExport(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	f := newFactFixture(t, d)
	base := fullExport(t, d)
	// Touch every entity so the incremental export runs every filtered query.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE users SET kyc=NOT kyc WHERE id=$1`, []any{f.user}},
		{`UPDATE eth_address_links SET revoked=true WHERE did=$1`, []any{f.did}},
		{`UPDATE groups SET is_org_admin=true WHERE id=$1`, []any{f.group}},
		{`UPDATE contracts SET deployed_by_user_id=$2, address='0x'||repeat('c3',20) WHERE id=$1`, []any{f.contract, f.user}},
		{`UPDATE execution_policy_revisions SET status='withdrawn' WHERE id=$1`, []any{f.policy}},
		{`UPDATE sanctioned_addresses SET address='0x'||repeat('f2',20) WHERE id=$1`, []any{f.sanction}},
		{`UPDATE preregistered_addresses SET org_id=$2 WHERE address=$1`, []any{f.prereg, f.otherOrg}},
	} {
		if _, err := d.conn.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	role := "node_policy_probe_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := d.conn.ExecContext(ctx, `CREATE ROLE `+role+` NOLOGIN`); err != nil {
		t.Fatalf("the probe needs a role it can create (superuser test database): %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.conn.ExecContext(context.Background(), `DROP OWNED BY `+role)
		_, _ = d.conn.ExecContext(context.Background(), `DROP ROLE `+role)
	})
	for table, columns := range nodePolicyFactDependencies {
		if _, err := d.conn.ExecContext(ctx, fmt.Sprintf(`GRANT SELECT (%s) ON %s TO %s`, strings.Join(columns, ","), table, role)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.conn.ExecContext(ctx, `GRANT SELECT ON node_policy_clock, node_policy_changes, node_policy_change_floor TO `+role); err != nil {
		t.Fatal(err)
	}
	asProbe := func(fn func(*sql.Tx) error) error {
		tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE `+role); err != nil {
			t.Fatal(err)
		}
		return fn(tx)
	}
	if err := asProbe(func(tx *sql.Tx) error {
		var s nodepolicy.Snapshot
		return exportNodeFacts(ctx, tx, &s)
	}); err != nil {
		t.Fatalf("full export reads a column outside the dependency set: %v", err)
	}
	var changes nodepolicy.FactChanges
	if err := asProbe(func(tx *sql.Tx) error {
		var err error
		changes, err = exportNodeFactChanges(ctx, tx, base)
		return err
	}); err != nil {
		t.Fatalf("incremental export reads a column outside the dependency set: %v", err)
	}
	if changes.Full || len(changes.Principals) == 0 || len(changes.Groups) == 0 || len(changes.Contracts) == 0 || len(changes.PolicyOrgs) == 0 || len(changes.Sanctions) == 0 {
		t.Fatalf("probe did not exercise every incremental query: %+v", changes)
	}
	// Negative control: the probe is effective.
	if _, err := d.conn.ExecContext(ctx, `REVOKE SELECT (kyc) ON users FROM `+role); err != nil {
		t.Fatal(err)
	}
	err := asProbe(func(tx *sql.Tx) error {
		var s nodepolicy.Snapshot
		return exportNodeFacts(ctx, tx, &s)
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("probe without users.kyc must be refused, got %v", err)
	}

	// Triggers: insert/delete unconditionally; update WHEN exactly the set
	// changed (no UPDATE OF list, which would ignore values set by BEFORE
	// triggers); truncate per statement.
	const (
		row, insert, del, update, truncate = 1, 4, 8, 16, 32
	)
	oldColumn := regexp.MustCompile(`\bold\.([a-z_]+)`)
	for table, columns := range nodePolicyFactDependencies {
		rows, err := d.conn.QueryContext(ctx, `SELECT t.tgtype, t.tgqual IS NOT NULL, cardinality(t.tgattr::int2[]), pg_get_triggerdef(t.oid)
			FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
			WHERE t.tgrelid=$1::regclass AND NOT t.tgisinternal AND p.proname LIKE 'node_policy_%'`, table)
		if err != nil {
			t.Fatal(err)
		}
		var rowTrigger, updateTrigger, truncateTrigger int
		for rows.Next() {
			var kind, attrs int
			var guarded bool
			var def string
			if err := rows.Scan(&kind, &guarded, &attrs, &def); err != nil {
				t.Fatal(err)
			}
			switch {
			case kind == row|insert|del && !guarded:
				rowTrigger++
			case kind == row|update && guarded && attrs == 0:
				updateTrigger++
				seen := map[string]bool{}
				for _, m := range oldColumn.FindAllStringSubmatch(def, -1) {
					seen[m[1]] = true
				}
				var got []string
				for c := range seen {
					got = append(got, c)
				}
				sort.Strings(got)
				want := slices.Clone(columns)
				sort.Strings(want)
				if !slices.Equal(got, want) || !strings.Contains(def, "IS DISTINCT FROM") {
					t.Errorf("%s: update trigger compares %v, dependency set %v: %s", table, got, want, def)
				}
			case kind == truncate:
				truncateTrigger++
			default:
				t.Errorf("%s: unexpected node policy trigger type %d (guarded %v, %d columns)", table, kind, guarded, attrs)
			}
		}
		rows.Close()
		if rowTrigger != 1 || updateTrigger != 1 || truncateTrigger != 1 {
			t.Errorf("%s: insert/delete=%d update=%d truncate=%d triggers, want one each", table, rowTrigger, updateTrigger, truncateTrigger)
		}
	}
}

// assertIncrementalMatchesFull checks that the incremental export from base
// produces exactly the full export and its delta (G11).
func assertIncrementalMatchesFull(t *testing.T, d *DB, base nodepolicy.Snapshot) nodepolicy.Snapshot {
	t.Helper()
	full := fullExport(t, d)
	if full.Version == base.Version {
		if string(canonicalFacts(t, full)) != string(canonicalFacts(t, base)) {
			t.Fatal("facts changed without a version bump")
		}
		return full
	}
	changes, err := d.ExportNodePolicyChanges(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if changes.Full {
		t.Fatal("incremental export fell back to a full export without a reason")
	}
	baseDigest := strings.Repeat("ab", 32)
	next, delta, err := nodepolicy.ApplyChanges(base, baseDigest, full.Header, changes)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonicalFacts(t, next), canonicalFacts(t, full); string(got) != string(want) {
		t.Fatalf("incremental snapshot differs from the full export\n got %s\nwant %s", got, want)
	}
	want, err := nodepolicy.BuildDelta(base, baseDigest, full)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(delta)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("incremental delta differs from the full diff\n got %s\nwant %s", gotJSON, wantJSON)
	}
	return next
}

// canonicalFacts orders every fact list by its key, so two snapshots with the
// same facts compare equal whatever order they were built in.
func canonicalFacts(t *testing.T, s nodepolicy.Snapshot) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var c nodepolicy.Snapshot
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	sort.Slice(c.Principals, func(i, j int) bool { return c.Principals[i].ID < c.Principals[j].ID })
	sort.Slice(c.Groups, func(i, j int) bool { return c.Groups[i].ID < c.Groups[j].ID })
	sort.Slice(c.Contracts, func(i, j int) bool { return c.Contracts[i].Address < c.Contracts[j].Address })
	sort.Slice(c.Policies, func(i, j int) bool {
		return c.Policies[i].OrgID+"\x00"+c.Policies[i].GroupID < c.Policies[j].OrgID+"\x00"+c.Policies[j].GroupID
	})
	sort.Slice(c.Sanctions, func(i, j int) bool {
		return c.Sanctions[i].OrgID+":"+c.Sanctions[i].Address < c.Sanctions[j].OrgID+":"+c.Sanctions[j].Address
	})
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNodePolicyTriggerDependenciesMutations is the behavioural half of G1:
// each dependency change bumps exactly once and the incremental export
// follows it; a change outside the set bumps nothing.
func TestNodePolicyTriggerDependenciesMutations(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	f := newFactFixture(t, d)
	bytecode := []byte("second-runtime")
	sum := sha256.Sum256(bytecode)
	draft := uuid.NewString()
	base := fullExport(t, d)
	for _, c := range []struct {
		name  string
		bumps bool
		sql   []string
		args  []any
	}{
		{"link revoked", true, []string{`UPDATE eth_address_links SET revoked=true WHERE did=$1`}, []any{f.did}},
		{"link unrevoked", true, []string{`UPDATE eth_address_links SET revoked=false WHERE did=$1`}, []any{f.did}},
		{"link did moves to another principal", true, []string{`UPDATE eth_address_links SET did=$2 WHERE did=$1`}, []any{f.did, f.otherDID}},
		{"link moves back", true, []string{`UPDATE eth_address_links SET did=$2 WHERE did=$1`}, []any{f.otherDID, f.did}},
		{"link address changes", true, []string{`UPDATE eth_address_links SET eth_address='0x2222222222222222222222222222222222222222' WHERE did=$1`}, []any{f.did}},
		{"membership moves to another principal", true, []string{`UPDATE user_memberships SET user_id=$2 WHERE id=$1`}, []any{f.membership, f.otherUser}},
		{"membership moves to another group", true, []string{`UPDATE user_memberships SET group_id=$2 WHERE id=$1`}, []any{f.membership, f.otherGroup}},
		{"membership expiry", true, []string{`UPDATE user_memberships SET expires_at='2031-01-01' WHERE id=$1`}, []any{f.membership}},
		{"contract address moves", true, []string{`UPDATE contracts SET address='0x'||repeat('c2',20) WHERE id=$1`}, []any{f.contract}},
		{"contract org moves", true, []string{`UPDATE contracts SET org_id=$2 WHERE id=$1`}, []any{f.contract, f.otherOrg}},
		{"group claims", true, []string{`UPDATE group_access SET claims=ARRAY['admin'] WHERE group_id=$1`}, []any{f.group}},
		{"grant moves to another group", true, []string{`UPDATE contract_grants SET group_id=$2 WHERE id=$1`}, []any{f.grant, f.otherGroup}},
		{"shared codehash", true, []string{`UPDATE shared_infrastructure SET codehash='0x'||repeat('1f',32) WHERE address=$1`}, []any{f.shared}},
		{"legacy ban flag", true, []string{`INSERT INTO access_policies(external_id,banned) VALUES($1,true)`}, []any{f.did}},
		{"legacy ban flag cleared", true, []string{`DELETE FROM access_policies WHERE external_id=$1`}, []any{f.did}},
		{"policy deactivation", true, []string{`UPDATE execution_policy_revisions SET status='withdrawn' WHERE id=$1`}, []any{f.policy}},
		{"policy draft inserted", false, []string{`INSERT INTO execution_policy_revisions(id,org_id,revision,status,source,policy_digest,solidity_source,solidity_digest,runtime_bytecode,runtime_digest,compiler)
			VALUES($1,$2,2,'draft','policy',repeat('cd',32),'contract Q {}',repeat('cd',32),$3,$4,'{}'::jsonb)`}, []any{draft, f.org, bytecode, hex.EncodeToString(sum[:])}},
		{"policy activation", true, []string{`UPDATE execution_policy_revisions SET status='active' WHERE id=$1`}, []any{draft}},
		{"sanction added", true, []string{`INSERT INTO sanctioned_addresses(org_id,address,reason) VALUES(NULL,'0x'||repeat('f3',20),'list')`}, nil},
		{"sanction removed", true, []string{`DELETE FROM sanctioned_addresses WHERE address='0x'||repeat('f3',20)`}, nil},
		{"pending address deleted", true, []string{`DELETE FROM preregistered_addresses WHERE address=$1`}, []any{f.prereg}},
		{"group deleted", true, []string{`DELETE FROM groups WHERE id=$1`}, []any{f.otherGroup}},
		{"principal deleted", true, []string{`DELETE FROM users WHERE id=$1`}, []any{f.otherUser}},
		{"principal inserted", true, []string{`INSERT INTO users(id,external_id,kyc) VALUES($1::uuid,'did:test:mutation-'||$1::text,true)`}, []any{uuid.NewString()}},
		{"contract deleted", true, []string{`DELETE FROM contracts WHERE id=$1`}, []any{f.contract}},
		// Outside the dependency set.
		{"users note and metadata", false, []string{`UPDATE users SET note='n', metadata='{"x":1}', updated_at=now(), auth_tenant_id='t' WHERE id=$1`}, []any{f.user}},
		{"same value", false, []string{`UPDATE users SET banned=banned, kyc=kyc WHERE id=$1`}, []any{f.user}},
		{"link metadata", false, []string{`UPDATE eth_address_links SET ens_name='a.eth', verified_at=now(), signature='s' WHERE did=$1`}, []any{f.did}},
		{"group name", false, []string{`UPDATE groups SET description='d', name='Renamed '||id::text WHERE id=$1`}, []any{f.group}},
		{"group methods and rate", false, []string{`UPDATE group_access SET allowed_methods=ARRAY['eth_call'], rate_limit_rps=5, verbose_errors=true WHERE group_id=$1`}, []any{f.group}},
		{"membership source", false, []string{`UPDATE user_memberships SET source='zk' WHERE user_id=$1`}, []any{f.user}},
		{"sanction reason", false, []string{`UPDATE sanctioned_addresses SET reason='other', source='list' WHERE id=$1`}, []any{f.sanction}},
		{"shared name", false, []string{`UPDATE shared_infrastructure SET name='Renamed', description='d' WHERE address=$1`}, []any{f.shared}},
		{"active policy source text", false, []string{`UPDATE execution_policy_revisions SET solidity_source='contract Q { }', activated_at=now() WHERE id=$1`}, []any{draft}},
		{"withdrawn policy edited", false, []string{`UPDATE execution_policy_revisions SET runtime_digest=runtime_digest||'' , revision=revision+10 WHERE id=$1`}, []any{f.policy}},
	} {
		before := policyVersion(t, d)
		err := d.WithTx(ctx, func(tx *Tx) error {
			for _, q := range c.sql {
				n := strings.Count(q, "$")
				if _, err := tx.tx.ExecContext(ctx, q, c.args[:min(n, len(c.args))]...); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		after := policyVersion(t, d)
		if c.bumps && after != before+1 {
			t.Fatalf("%s: version %d -> %d, want one bump", c.name, before, after)
		}
		if !c.bumps && after != before {
			t.Fatalf("%s: a change outside the dependency set bumped the clock %d -> %d", c.name, before, after)
		}
		base = assertIncrementalMatchesFull(t, d, base)
	}
}

func TestIncrementalExportFallsBackWhenTheLogCannotDescribeTheGap(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	f := newFactFixture(t, d)
	base := fullExport(t, d)
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET kyc=NOT kyc WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	// An acknowledgement past base prunes changes base still needs.
	if err := d.AcknowledgeNodePolicy(ctx, "producer", nodepolicy.AppliedState{Version: base.Version + 1, Digest: strings.Repeat("a", 64), ExpiresAt: 2000}); err != nil {
		t.Fatal(err)
	}
	changes, err := d.ExportNodePolicyChanges(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Full {
		t.Fatal("a pruned gap must fall back to the full export")
	}
	// A truncation records no keys: full export.
	base = fullExport(t, d)
	if _, err := d.conn.ExecContext(ctx, `TRUNCATE sanctioned_addresses`); err != nil {
		t.Fatal(err)
	}
	if policyVersion(t, d) != int64(base.Version)+1 {
		t.Fatal("truncate did not bump the clock")
	}
	changes, err = d.ExportNodePolicyChanges(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Full {
		t.Fatal("a truncation must fall back to the full export")
	}
	// A base ahead of the database is a conflict, never an empty change set.
	ahead := base
	ahead.Version += 100
	if _, err := d.ExportNodePolicyChanges(ctx, ahead); err == nil {
		t.Fatal("base ahead of the clock accepted")
	}
}

// TestIncrementalExportEqualsFullDiff (G11) drives a random sequence of fact
// changes, one transaction per step, and checks after every step that the
// incremental export from the previous generation equals the full export and
// its full diff.
func TestIncrementalExportEqualsFullDiff(t *testing.T) {
	d := setupTestDB(t)
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	g := &factGenerator{t: t, d: d, rng: rng}
	for i := 0; i < 4; i++ {
		g.exec(`INSERT INTO organizations(id,slug,name) VALUES($1::uuid,'g11-'||$1::text,'G11 '||$1::text)`, uuid.NewString())
	}
	for i := 0; i < 12; i++ {
		g.step(g.opsByName("insertUser", "insertGroup", "insertContract", "insertLink", "insertMembership"))
	}
	history := []nodepolicy.Snapshot{fullExport(t, d)}
	bumps := 0
	for step := 0; step < 250; step++ {
		g.step(nil)
		// From the previous generation, and from one several steps back (a
		// publisher that missed generations, or a node that applied an older one).
		latest := history[len(history)-1]
		next := assertIncrementalMatchesFull(t, d, latest)
		if older := history[max(0, len(history)-1-rng.Intn(6))]; older.Version != latest.Version {
			assertIncrementalMatchesFull(t, d, older)
		}
		if next.Version != latest.Version {
			bumps++
			history = append(history, next)
		}
	}
	if bumps < 100 {
		t.Fatalf("only %d of 250 steps changed facts; the generator is not exercising the export", bumps)
	}
}

// A grant committed concurrently with a move of the granted contract's
// address: the group's embedded address must follow the move.
func TestIncrementalExportSeesGrantRacingAnAddressMove(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	f := newFactFixture(t, d)
	base := fullExport(t, d)
	b, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Rollback()
	if _, err := b.ExecContext(ctx, `INSERT INTO contract_grants(group_id,contract_id) VALUES($1,$2)`, f.otherGroup, f.contract); err != nil {
		t.Fatal(err)
	}
	moved := make(chan error, 1)
	go func() {
		_, err := d.conn.ExecContext(ctx, `UPDATE contracts SET address='0x'||repeat('c4',20) WHERE id=$1`, f.contract)
		moved <- err
	}()
	// Wait until the move is blocked on the clock that b holds.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := d.conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE contracts SET address%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the address move never waited on the clock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
	assertIncrementalMatchesFull(t, d, base)
}

// factGenerator issues random, mostly valid fact changes. A step that hits a
// constraint is rolled back, which is itself a case: no bump, no change.
type factGenerator struct {
	t   *testing.T
	d   *DB
	rng *rand.Rand
}

func (g *factGenerator) exec(q string, args ...any) {
	g.t.Helper()
	if _, err := g.d.conn.ExecContext(context.Background(), q, args...); err != nil {
		g.t.Fatalf("%v\n%s", err, q)
	}
}

func (g *factGenerator) pick(q string, args ...any) string {
	var out sql.NullString
	err := g.d.conn.QueryRowContext(context.Background(), q+` ORDER BY random() LIMIT 1`, args...).Scan(&out)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		g.t.Fatalf("%v\n%s", err, q)
	}
	return out.String
}

func (g *factGenerator) address(pool byte) string {
	return fmt.Sprintf("0x%02x%038x", pool, g.rng.Intn(40))
}

// mixedCase returns the address with a fixed, mixed letter case, as clients
// send checksummed addresses. Tables unique on the raw address get one casing
// per address; the export keys every one by its lower case.
func mixedCase(address string) string {
	b := []byte(address)
	for i := 2; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'f' && i%2 == 0 {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// anyCase is lower or mixed case at random, for tables unique on lower().
func (g *factGenerator) anyCase(address string) string {
	if g.rng.Intn(2) == 0 {
		return mixedCase(address)
	}
	return address
}

type factOp struct {
	name string
	run  func(tx *sql.Tx) error
}

func (g *factGenerator) ops() []factOp {
	ctx := context.Background()
	x := func(tx *sql.Tx, q string, args ...any) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	org := func() string { return g.pick(`SELECT id::text FROM organizations WHERE slug LIKE 'g11-%'`) }
	user := func() string { return g.pick(`SELECT id::text FROM users`) }
	did := func() string { return g.pick(`SELECT external_id FROM users`) }
	group := func() string { return g.pick(`SELECT id::text FROM groups`) }
	contract := func() string { return g.pick(`SELECT id::text FROM contracts`) }
	nullable := func(v string) any {
		if v == "" || g.rng.Intn(4) == 0 {
			return nil
		}
		return v
	}
	claims := func() []string {
		all := []string{"deploy", "upgrade", "admin"}
		var out []string
		for _, c := range all {
			if g.rng.Intn(2) == 0 {
				out = append(out, c)
			}
		}
		return out
	}
	policy := func(tx *sql.Tx, orgID, status string) error {
		code := make([]byte, 16+g.rng.Intn(16))
		g.rng.Read(code)
		sum := sha256.Sum256(code)
		digest := fmt.Sprintf("%064x", g.rng.Int63())
		return x(tx, `INSERT INTO execution_policy_revisions(org_id,revision,status,source,policy_digest,solidity_source,solidity_digest,runtime_bytecode,runtime_digest,compiler)
			SELECT $1, COALESCE(max(revision),0)+1, $2, 'policy', $3, 'contract P {}', $3, $4, $5, '{}'::jsonb FROM execution_policy_revisions WHERE org_id=$1`,
			orgID, status, digest, code, hex.EncodeToString(sum[:]))
	}
	return []factOp{
		{"insertUser", func(tx *sql.Tx) error {
			id := uuid.NewString()
			return x(tx, `INSERT INTO users(id,external_id,kyc,banned) VALUES($1::uuid,'did:test:g11-'||$1::text,$2,$3)`, id, g.rng.Intn(2) == 0, g.rng.Intn(5) == 0)
		}},
		{"toggleUser", func(tx *sql.Tx) error {
			return x(tx, `UPDATE users SET kyc=CASE WHEN $2 THEN NOT kyc ELSE kyc END, banned=CASE WHEN $2 THEN banned ELSE NOT banned END WHERE id::text=$1`, user(), g.rng.Intn(2) == 0)
		}},
		{"noiseUser", func(tx *sql.Tx) error {
			return x(tx, `UPDATE users SET note=$2, metadata=jsonb_build_object('n',$2), updated_at=now() WHERE id::text=$1`, user(), strconv.Itoa(g.rng.Int()))
		}},
		{"renameDID", func(tx *sql.Tx) error {
			return x(tx, `UPDATE users SET external_id='did:test:g11-renamed-'||$2 WHERE id::text=$1`, user(), uuid.NewString())
		}},
		{"deleteUser", func(tx *sql.Tx) error { return x(tx, `DELETE FROM users WHERE id::text=$1`, user()) }},
		{"insertLink", func(tx *sql.Tx) error {
			target := did()
			if g.rng.Intn(5) == 0 {
				target = "did:test:g11-unknown-" + strconv.Itoa(g.rng.Intn(3))
			}
			return x(tx, `INSERT INTO eth_address_links(did,eth_address,link_type) VALUES($1,$2,'system')`, target, g.anyCase(g.address(0x11)))
		}},
		{"revokeLink", func(tx *sql.Tx) error {
			return x(tx, `UPDATE eth_address_links SET revoked=NOT revoked WHERE id::text=$1`, g.pick(`SELECT id::text FROM eth_address_links`))
		}},
		{"moveLink", func(tx *sql.Tx) error {
			return x(tx, `UPDATE eth_address_links SET did=$2 WHERE id::text=$1`, g.pick(`SELECT id::text FROM eth_address_links`), did())
		}},
		{"readdressLink", func(tx *sql.Tx) error {
			return x(tx, `UPDATE eth_address_links SET eth_address=$2 WHERE id::text=$1`, g.pick(`SELECT id::text FROM eth_address_links`), g.address(0x11))
		}},
		{"noiseLink", func(tx *sql.Tx) error {
			return x(tx, `UPDATE eth_address_links SET ens_name=$2, verified_at=now() WHERE id::text=$1`, g.pick(`SELECT id::text FROM eth_address_links`), strconv.Itoa(g.rng.Int()))
		}},
		{"deleteLink", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM eth_address_links WHERE id::text=$1`, g.pick(`SELECT id::text FROM eth_address_links`))
		}},
		{"legacyBan", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO access_policies(external_id,banned,kyc) VALUES($1,$2,$3) ON CONFLICT(external_id) DO UPDATE SET banned=EXCLUDED.banned, kyc=EXCLUDED.kyc`, did(), g.rng.Intn(2) == 0, g.rng.Intn(2) == 0)
		}},
		{"legacyBanCleared", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM access_policies WHERE external_id=$1`, g.pick(`SELECT external_id FROM access_policies`))
		}},
		{"insertMembership", func(tx *sql.Tx) error {
			var expiry any
			if g.rng.Intn(3) == 0 {
				expiry = time.Unix(1_900_000_000+int64(g.rng.Intn(1000)), 0).UTC()
			}
			return x(tx, `INSERT INTO user_memberships(user_id,group_id,expires_at) VALUES($1::uuid,$2::uuid,$3)`, user(), group(), expiry)
		}},
		{"moveMembership", func(tx *sql.Tx) error {
			if g.rng.Intn(2) == 0 {
				return x(tx, `UPDATE user_memberships SET user_id=$2::uuid WHERE id::text=$1`, g.pick(`SELECT id::text FROM user_memberships`), user())
			}
			return x(tx, `UPDATE user_memberships SET group_id=$2::uuid WHERE id::text=$1`, g.pick(`SELECT id::text FROM user_memberships`), group())
		}},
		{"expireMembership", func(tx *sql.Tx) error {
			return x(tx, `UPDATE user_memberships SET expires_at=CASE WHEN expires_at IS NULL THEN '2031-05-05'::timestamp ELSE NULL END, source='admin' WHERE id::text=$1`, g.pick(`SELECT id::text FROM user_memberships`))
		}},
		{"deleteMembership", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM user_memberships WHERE id::text=$1`, g.pick(`SELECT id::text FROM user_memberships`))
		}},
		{"insertGroup", func(tx *sql.Tx) error {
			id := uuid.NewString()
			if err := x(tx, `INSERT INTO groups(id,org_id,slug,name,depth,path,is_org_admin) VALUES($1::uuid,$2::uuid,'g-'||$1::text,'G '||$1::text,0,'g-'||$1::text,$3)`, id, org(), g.rng.Intn(4) == 0); err != nil {
				return err
			}
			if g.rng.Intn(4) == 0 {
				return nil
			}
			return x(tx, `INSERT INTO group_access(group_id,claims,allowed_methods) VALUES($1,$2,ARRAY['eth_sendRawTransaction'])`, id, claims())
		}},
		{"toggleOrgAdmin", func(tx *sql.Tx) error {
			return x(tx, `UPDATE groups SET is_org_admin=NOT is_org_admin WHERE id::text=$1`, group())
		}},
		{"moveGroupOrg", func(tx *sql.Tx) error {
			return x(tx, `UPDATE groups SET org_id=$2::uuid WHERE id::text=$1`, group(), org())
		}},
		{"groupClaims", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO group_access(group_id,claims,allowed_methods) VALUES($1::uuid,$2,ARRAY['eth_call']) ON CONFLICT(group_id) DO UPDATE SET claims=EXCLUDED.claims`, group(), claims())
		}},
		{"noiseGroup", func(tx *sql.Tx) error {
			return x(tx, `UPDATE group_access SET allowed_methods=ARRAY['eth_call','x'||$2], rate_limit_rps=$3 WHERE group_id::text=$1`, group(), strconv.Itoa(g.rng.Int()), g.rng.Intn(50))
		}},
		{"deleteGroupAccess", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM group_access WHERE group_id::text=$1`, group())
		}},
		{"deleteGroup", func(tx *sql.Tx) error { return x(tx, `DELETE FROM groups WHERE id::text=$1`, group()) }},
		{"insertContract", func(tx *sql.Tx) error {
			pool := []byte{0xc1, 0xe1, 0xd1}[g.rng.Intn(3)]
			return x(tx, `INSERT INTO contracts(org_id,address,name,deployed_by_user_id) VALUES($1::uuid,$2,'C',$3::uuid)`, org(), g.anyCase(g.address(pool)), nullable(user()))
		}},
		{"readdressContract", func(tx *sql.Tx) error {
			pool := []byte{0xc1, 0xe1, 0xd1}[g.rng.Intn(3)]
			return x(tx, `UPDATE contracts SET address=$2 WHERE id::text=$1`, contract(), g.anyCase(g.address(pool)))
		}},
		{"moveContractOrg", func(tx *sql.Tx) error {
			return x(tx, `UPDATE contracts SET org_id=$2::uuid WHERE id::text=$1`, contract(), org())
		}},
		{"deployer", func(tx *sql.Tx) error {
			return x(tx, `UPDATE contracts SET deployed_by_user_id=$2::uuid WHERE id::text=$1`, contract(), nullable(user()))
		}},
		{"noiseContract", func(tx *sql.Tx) error {
			return x(tx, `UPDATE contracts SET name='N'||$2, metadata=jsonb_build_object('n',$2), abi='[]' WHERE id::text=$1`, contract(), strconv.Itoa(g.rng.Int()))
		}},
		{"deleteContract", func(tx *sql.Tx) error { return x(tx, `DELETE FROM contracts WHERE id::text=$1`, contract()) }},
		{"insertGrant", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO contract_grants(group_id,contract_id) VALUES($1::uuid,$2::uuid)`, group(), contract())
		}},
		{"moveGrant", func(tx *sql.Tx) error {
			grant := g.pick(`SELECT id::text FROM contract_grants`)
			if g.rng.Intn(2) == 0 {
				return x(tx, `UPDATE contract_grants SET group_id=$2::uuid WHERE id::text=$1`, grant, group())
			}
			return x(tx, `UPDATE contract_grants SET contract_id=$2::uuid WHERE id::text=$1`, grant, contract())
		}},
		{"noiseGrant", func(tx *sql.Tx) error {
			return x(tx, `UPDATE contract_grants SET claims=ARRAY['upgrade'], functions='{"f":1}', event_rules='{}' WHERE id::text=$1`, g.pick(`SELECT id::text FROM contract_grants`))
		}},
		{"deleteGrant", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM contract_grants WHERE id::text=$1`, g.pick(`SELECT id::text FROM contract_grants`))
		}},
		{"insertShared", func(tx *sql.Tx) error {
			pool := []byte{0xe1, 0xc1}[g.rng.Intn(2)]
			return x(tx, `INSERT INTO shared_infrastructure(address,name,codehash) VALUES($1,'S',$2)`, mixedCase(g.address(pool)), nullable(fmt.Sprintf("0x%064x", g.rng.Int63())))
		}},
		{"sharedCodehash", func(tx *sql.Tx) error {
			return x(tx, `UPDATE shared_infrastructure SET codehash=$2 WHERE address=$1`, g.pick(`SELECT address FROM shared_infrastructure`), nullable(fmt.Sprintf("0x%064x", g.rng.Int63())))
		}},
		{"deleteShared", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM shared_infrastructure WHERE address=$1`, g.pick(`SELECT address FROM shared_infrastructure`))
		}},
		{"insertPending", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO preregistered_addresses(org_id,address) VALUES($1::uuid,$2)`, org(), mixedCase(g.address(0xd1)))
		}},
		{"movePending", func(tx *sql.Tx) error {
			return x(tx, `UPDATE preregistered_addresses SET org_id=$2::uuid, note='moved' WHERE address=$1`, g.pick(`SELECT address FROM preregistered_addresses`), org())
		}},
		{"deletePending", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM preregistered_addresses WHERE address=$1`, g.pick(`SELECT address FROM preregistered_addresses`))
		}},
		{"insertSanction", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO sanctioned_addresses(org_id,address,reason) VALUES($1::uuid,$2,'r')`, nullable(org()), mixedCase(g.address(0xf1)))
		}},
		{"readdressSanction", func(tx *sql.Tx) error {
			return x(tx, `UPDATE sanctioned_addresses SET address=$2, reason='x' WHERE id::text=$1`, g.pick(`SELECT id::text FROM sanctioned_addresses`), mixedCase(g.address(0xf1)))
		}},
		{"deleteSanction", func(tx *sql.Tx) error {
			return x(tx, `DELETE FROM sanctioned_addresses WHERE id::text=$1`, g.pick(`SELECT id::text FROM sanctioned_addresses`))
		}},
		{"activatePolicy", func(tx *sql.Tx) error {
			o := org()
			if err := x(tx, `UPDATE execution_policy_revisions SET status='superseded' WHERE org_id::text=$1 AND status='active'`, o); err != nil {
				return err
			}
			return policy(tx, o, "active")
		}},
		{"draftPolicy", func(tx *sql.Tx) error { return policy(tx, org(), "draft") }},
		{"withdrawPolicy", func(tx *sql.Tx) error {
			return x(tx, `UPDATE execution_policy_revisions SET status='withdrawn' WHERE id::text=$1`, g.pick(`SELECT id::text FROM execution_policy_revisions WHERE status='active'`))
		}},
		{"insertOrg", func(tx *sql.Tx) error {
			return x(tx, `INSERT INTO organizations(id,slug,name) VALUES($1::uuid,'g11-'||$1::text,'G11 '||$1::text)`, uuid.NewString())
		}},
		{"deleteOrg", func(tx *sql.Tx) error {
			if g.rng.Intn(4) != 0 {
				return nil
			}
			return x(tx, `DELETE FROM organizations WHERE id::text=$1`, org())
		}},
	}
}

func (g *factGenerator) opsByName(names ...string) []factOp {
	var out []factOp
	for _, op := range g.ops() {
		if slices.Contains(names, op.name) {
			out = append(out, op)
		}
	}
	return out
}

// step runs one to three random operations in one transaction.
func (g *factGenerator) step(from []factOp) {
	g.t.Helper()
	if from == nil {
		from = g.ops()
	}
	tx, err := g.d.conn.BeginTx(context.Background(), nil)
	if err != nil {
		g.t.Fatal(err)
	}
	defer tx.Rollback()
	for n := 1 + g.rng.Intn(3); n > 0; n-- {
		if err := from[g.rng.Intn(len(from))].run(tx); err != nil {
			return // constraint or empty pick: roll back
		}
	}
	if err := tx.Commit(); err != nil {
		g.t.Fatal(err)
	}
}

// The runtime and the admin role both write fact tables. The runtime role may
// change the change log and the floor only through the SECURITY DEFINER
// functions, and a temporary table cannot stand in for the real floor.
func TestChangeLogIsWritableOnlyThroughItsFunctions(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	asRole := func(role string, fn func(*sql.Tx) error) error {
		tx, err := d.conn.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE `+role); err != nil {
			t.Fatal(err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	for _, role := range []string{"privacy_proxy_app", "privacy_proxy_admin"} {
		before := policyVersion(t, d)
		if err := asRole(role, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID)
			return err
		}); err != nil {
			t.Fatalf("%s cannot write a fact: %v", role, err)
		}
		if policyVersion(t, d) != before+1 {
			t.Fatalf("%s's fact write did not bump the clock", role)
		}
		if role != "privacy_proxy_app" {
			continue // the admin role holds every privilege by design (058)
		}
		for _, q := range []string{`DELETE FROM node_policy_changes`, `UPDATE node_policy_change_floor SET version=1`, `UPDATE node_policy_clock SET version=version+1`, `INSERT INTO node_policy_changes VALUES (1,'full','*')`} {
			err := asRole(role, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err })
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("%s: %q must be refused, got %v", role, q, err)
			}
		}
	}
	// A temporary table named like the floor does not capture the prune.
	acked := policyVersion(t, d)
	if err := asRole("privacy_proxy_app", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE node_policy_change_floor (singleton BOOLEAN PRIMARY KEY, version BIGINT) ON COMMIT DROP`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_policy_change_floor VALUES (true, 1)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `SELECT node_policy_prune($1 + 1000000)`, acked)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var floor int64
	var left int
	if err := d.conn.QueryRowContext(ctx, `SELECT (SELECT version FROM public.node_policy_change_floor), (SELECT count(*) FROM public.node_policy_changes WHERE version <= $1)`, acked).Scan(&floor, &left); err != nil {
		t.Fatal(err)
	}
	if floor != acked || left != 0 {
		t.Fatalf("prune: floor %d (want %d, capped at the clock), %d rows left at or below it", floor, acked, left)
	}
}

// Without an acknowledging publisher the log stays bounded: every 1,024
// versions the bump drops what is more than 8,192 versions old.
func TestChangeLogIsBoundedWithoutAPublisher(t *testing.T) {
	d := setupTestDB(t)
	ctx := context.Background()
	userID, _ := cacheGenFixtures(t, d, ctx)
	start := policyVersion(t, d)
	next := (start/1024+9)*1024 - 1 // one below a multiple of 1,024 above 8,192
	if _, err := d.conn.ExecContext(ctx, `INSERT INTO node_policy_changes VALUES ($1,'principal','old')`, start); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE node_policy_clock SET version=$1`, next); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var floor int64
	var old int
	if err := d.conn.QueryRowContext(ctx, `SELECT (SELECT version FROM node_policy_change_floor), (SELECT count(*) FROM node_policy_changes WHERE resource_key='old')`).Scan(&floor, &old); err != nil {
		t.Fatal(err)
	}
	if floor != next+1-8192 || old != 0 {
		t.Fatalf("floor %d (want %d), old rows %d", floor, next+1-8192, old)
	}
}
