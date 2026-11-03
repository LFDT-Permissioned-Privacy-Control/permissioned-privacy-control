package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/policydsl"
)

// ExportNodePolicySnapshot reads the watermark first under repeatable-read so
// every following row belongs to that same committed database generation.
func (d *DB) ExportNodePolicySnapshot(ctx context.Context, network nodepolicy.Network, at time.Time, lifetime time.Duration) (nodepolicy.Snapshot, error) {
	var out nodepolicy.Snapshot
	if lifetime <= 0 || lifetime > nodepolicy.MaxMessageLifetime {
		return out, fmt.Errorf("invalid fact lifetime")
	}
	tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.Header = nodepolicy.Header{Network: network, IssuedAt: at.Unix(), ExpiresAt: at.Add(lifetime).Unix()}
	if err := tx.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&out.Version); err != nil {
		return out, err
	}
	if err := exportNodeFacts(ctx, tx, &out); err != nil {
		return nodepolicy.Snapshot{}, err
	}
	if _, err := nodepolicy.Pin(out); err != nil {
		return nodepolicy.Snapshot{}, fmt.Errorf("invalid exported facts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nodepolicy.Snapshot{}, err
	}
	return out, nil
}

// nodePolicyFactDependencies is every column the fact export reads, per table
// (the dependency set of RD-1411 §5.1). The fact clock bumps on an update only
// when one of these columns changes (migrations 075 and 083).
// TestNodePolicyTriggerDependenciesMatchExport runs both exports as a role
// that may read only these columns and checks the triggers compare exactly
// them, so adding a column to an export query without adding it here (and to
// the trigger) fails that test.
var nodePolicyFactDependencies = map[string][]string{
	"users":                      {"id", "external_id", "kyc", "banned"},
	"access_policies":            {"external_id", "banned"},
	"eth_address_links":          {"did", "eth_address", "revoked"},
	"user_memberships":           {"user_id", "group_id", "expires_at"},
	"groups":                     {"id", "org_id", "is_org_admin"},
	"group_access":               {"group_id", "claims"},
	"contract_grants":            {"group_id", "contract_id"},
	"contracts":                  {"id", "address", "org_id", "deployed_by_user_id"},
	"shared_infrastructure":      {"address", "codehash"},
	"preregistered_addresses":    {"address", "org_id"},
	"execution_policy_revisions": {"org_id", "revision", "policy_digest", "runtime_digest", "runtime_bytecode", "artifact_set", "status"},
	"sanctioned_addresses":       {"org_id", "address"},
}

// factScope selects which facts an export reads: every fact (full) or only
// the given keys of each kind (incremental). A nil key list in a filtered
// scope reads nothing of that kind.
type factScope struct {
	full                                                 bool
	principals, groups, contracts, policyOrgs, sanctions []string
}

// filtered returns the query for the full export, or with the key filter
// clause when the scope is incremental. Both paths share the query text, so
// they cannot drift apart.
func (s factScope) query(base, filter, order string, keys []string) (string, []any, bool) {
	if s.full {
		return base + " " + order, nil, true
	}
	if len(keys) == 0 {
		return "", nil, false
	}
	return base + " " + filter + " " + order, []any{keys}, true
}

func exportNodeFacts(ctx context.Context, q DBTX, out *nodepolicy.Snapshot) error {
	return exportNodeFactScope(ctx, q, factScope{full: true}, out)
}

func exportNodeFactScope(ctx context.Context, q DBTX, scope factScope, out *nodepolicy.Snapshot) error {
	run := func(base, filter, order string, keys []string, scan func(*sql.Rows) error) error {
		query, args, ok := scope.query(base, filter, order, keys)
		if !ok {
			return nil
		}
		return nodePolicyRows(ctx, q, query, scan, args...)
	}
	principals := map[string]int{}
	err := run(`SELECT u.id::text,u.kyc,(u.banned OR COALESCE(p.banned,false))
        FROM users u LEFT JOIN access_policies p ON p.external_id=u.external_id`, `WHERE u.id = ANY($1::uuid[])`, `ORDER BY u.id`, scope.principals, func(r *sql.Rows) error {
		var p nodepolicy.Principal
		if err := r.Scan(&p.ID, &p.KYC, &p.Banned); err != nil {
			return err
		}
		principals[p.ID] = len(out.Principals)
		out.Principals = append(out.Principals, p)
		return nil
	})
	if err != nil {
		return err
	}
	err = run(`SELECT DISTINCT u.id::text,lower(e.eth_address)
        FROM eth_address_links e JOIN users u ON u.external_id=e.did
        WHERE e.revoked=false`, `AND u.id = ANY($1::uuid[])`, `ORDER BY 1,2`, scope.principals, func(r *sql.Rows) error {
		var id, address string
		if err := r.Scan(&id, &address); err != nil {
			return err
		}
		i, ok := principals[id]
		if !ok {
			return fmt.Errorf("linked principal missing from snapshot")
		}
		out.Principals[i].LinkedAddresses = append(out.Principals[i].LinkedAddresses, address)
		return nil
	})
	if err != nil {
		return err
	}
	err = run(`SELECT user_id::text,group_id::text,expires_at FROM user_memberships`, `WHERE user_id = ANY($1::uuid[])`, `ORDER BY user_id,group_id`, scope.principals, func(r *sql.Rows) error {
		var id string
		var m nodepolicy.Membership
		var expiry sql.NullTime
		if err := r.Scan(&id, &m.GroupID, &expiry); err != nil {
			return err
		}
		if expiry.Valid {
			m.ExpiresAt = expiry.Time.Unix()
		}
		i, ok := principals[id]
		if !ok {
			return fmt.Errorf("membership principal missing from snapshot")
		}
		out.Principals[i].Memberships = append(out.Principals[i].Memberships, m)
		return nil
	})
	if err != nil {
		return err
	}
	groups := map[string]int{}
	err = run(`SELECT g.id::text,g.org_id::text,g.is_org_admin,to_json(COALESCE(a.claims,'{}'::text[]))
        FROM groups g LEFT JOIN group_access a ON a.group_id=g.id`, `WHERE g.id = ANY($1::uuid[])`, `ORDER BY g.id`, scope.groups, func(r *sql.Rows) error {
		var g nodepolicy.Group
		var raw []byte
		if err := r.Scan(&g.ID, &g.OrgID, &g.OrgAdmin, &raw); err != nil {
			return err
		}
		claims, err := nodeClaimMask(raw)
		if err != nil {
			return err
		}
		g.Claims = claims
		groups[g.ID] = len(out.Groups)
		out.Groups = append(out.Groups, g)
		return nil
	})
	if err != nil {
		return err
	}
	err = run(`SELECT cg.group_id::text,lower(c.address)
        FROM contract_grants cg JOIN contracts c ON c.id=cg.contract_id`, `WHERE cg.group_id = ANY($1::uuid[])`, `ORDER BY cg.group_id,c.address`, scope.groups, func(r *sql.Rows) error {
		var id string
		var grant nodepolicy.ContractClaim
		if err := r.Scan(&id, &grant.Address); err != nil {
			return err
		}
		i, ok := groups[id]
		if !ok {
			return fmt.Errorf("claim group missing from snapshot")
		}
		// Match rbac.Resolver.groupPerms: group_access claims apply only
		// to that group's granted targets. contract_grants.claims is legacy.
		grant.Claims = out.Groups[i].Claims
		out.Groups[i].ContractClaims = append(out.Groups[i].ContractClaims, grant)
		return nil
	})
	if err != nil {
		return err
	}
	// Filtering both sides of the full join on the lower-case address is the
	// same as filtering the joined row on lower(COALESCE(c.address,s.address)):
	// a row's two sides always share that address.
	contracts := `SELECT lower(COALESCE(c.address,s.address)),COALESCE(c.org_id::text,''),s.address IS NOT NULL,lower(COALESCE(s.codehash,'')),COALESCE(c.deployed_by_user_id::text,'')
        FROM contracts c FULL JOIN shared_infrastructure s ON lower(c.address)=lower(s.address)`
	if !scope.full {
		contracts = `SELECT lower(COALESCE(c.address,s.address)),COALESCE(c.org_id::text,''),s.address IS NOT NULL,lower(COALESCE(s.codehash,'')),COALESCE(c.deployed_by_user_id::text,'')
        FROM (SELECT address,org_id,deployed_by_user_id FROM contracts WHERE lower(address) = ANY($1)) c
        FULL JOIN (SELECT address,codehash FROM shared_infrastructure WHERE lower(address) = ANY($1)) s ON lower(c.address)=lower(s.address)`
	}
	err = run(contracts, ``, `ORDER BY 1`, scope.contracts, func(r *sql.Rows) error {
		var c nodepolicy.Contract
		if err := r.Scan(&c.Address, &c.OrgID, &c.SharedInfrastructure, &c.CodeHash, &c.DeployerPrincipalID); err != nil {
			return err
		}
		out.Contracts = append(out.Contracts, c)
		return nil
	})
	if err != nil {
		return err
	}
	// A registered owner always wins over stale preregistration. Conflicting
	// pending owners fail the export instead of selecting one tenant by order.
	err = run(`SELECT lower(p.address),min(p.org_id::text),count(DISTINCT p.org_id),bool_or(s.address IS NOT NULL)
        FROM preregistered_addresses p LEFT JOIN shared_infrastructure s ON lower(s.address)=lower(p.address)
        WHERE NOT EXISTS (SELECT 1 FROM contracts c WHERE lower(c.address)=lower(p.address))`, `AND lower(p.address) = ANY($1)`,
		`GROUP BY lower(p.address) ORDER BY 1`, scope.contracts, func(r *sql.Rows) error {
			c := nodepolicy.Contract{Pending: true}
			var owners int
			var shared bool
			if err := r.Scan(&c.Address, &c.OrgID, &owners, &shared); err != nil {
				return err
			}
			if owners != 1 || shared {
				return fmt.Errorf("ambiguous pending contract ownership")
			}
			out.Contracts = append(out.Contracts, c)
			return nil
		})
	if err != nil {
		return err
	}
	err = run(`SELECT org_id::text,revision,policy_digest,runtime_digest,runtime_bytecode,artifact_set
        FROM execution_policy_revisions WHERE status='active'`, `AND org_id = ANY($1::uuid[])`, `ORDER BY org_id`, scope.policyOrgs, func(r *sql.Rows) error {
		var p nodepolicy.PolicyArtifact
		var raw []byte
		if err := r.Scan(&p.OrgID, &p.Revision, &p.PolicyDigest, &p.RuntimeDigest, &p.Bytecode, &raw); err != nil {
			return err
		}
		if raw == nil {
			out.Policies = append(out.Policies, p)
		} else {
			set, err := policydsl.DecodeArtifactSet(raw)
			if err != nil {
				return err
			}
			if set.PolicyDigest != p.PolicyDigest {
				return fmt.Errorf("execution artifact document mismatch")
			}
			groups := make([]string, 0, len(set.Groups))
			for group := range set.Groups {
				groups = append(groups, group)
			}
			sort.Strings(groups)
			for _, group := range groups {
				a := set.Groups[group]
				out.Policies = append(out.Policies, nodepolicy.PolicyArtifact{OrgID: p.OrgID, GroupID: group, Revision: p.Revision, PolicyDigest: a.PolicyDigest, RuntimeDigest: a.RuntimeDigest, Bytecode: a.RuntimeBytecode})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return run(`SELECT COALESCE(org_id::text,''),lower(address) FROM sanctioned_addresses`, `WHERE COALESCE(org_id::text,'') || ':' || lower(address) = ANY($1)`,
		`ORDER BY org_id NULLS FIRST,address`, scope.sanctions, func(r *sql.Rows) error {
			var s nodepolicy.Sanction
			if err := r.Scan(&s.OrgID, &s.Address); err != nil {
				return err
			}
			out.Sanctions = append(out.Sanctions, s)
			return nil
		})
}

// maxIncrementalKeys bounds an incremental export; a larger change set is
// cheaper to export in full.
const maxIncrementalKeys = 4096

// ExportNodePolicyChanges reads, in one repeatable-read snapshot, what changed
// since the base generation the node holds: the clock version, the changed
// keys from the change log, and the current facts for exactly those keys
// (RD-1411 §5.6). Full is set when the log cannot describe the whole gap
// (pruned past base, a truncation, or too many keys); the caller then exports
// everything. A base ahead of the clock is a conflict.
func (d *DB) ExportNodePolicyChanges(ctx context.Context, base nodepolicy.Snapshot) (nodepolicy.FactChanges, error) {
	tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nodepolicy.FactChanges{}, err
	}
	defer tx.Rollback()
	out, err := exportNodeFactChanges(ctx, tx, base)
	if err != nil {
		return nodepolicy.FactChanges{}, err
	}
	if err := tx.Commit(); err != nil {
		return nodepolicy.FactChanges{}, err
	}
	return out, nil
}

var uuidKey = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func exportNodeFactChanges(ctx context.Context, q DBTX, base nodepolicy.Snapshot) (nodepolicy.FactChanges, error) {
	var out nodepolicy.FactChanges
	var floor uint64
	if err := q.QueryRowContext(ctx, `SELECT c.version, f.version FROM node_policy_clock c, node_policy_change_floor f WHERE c.singleton AND f.singleton`).Scan(&out.Version, &floor); err != nil {
		return out, err
	}
	if base.Version == 0 || out.Version < base.Version {
		return nodepolicy.FactChanges{}, nodepolicy.ErrFeedConflict
	}
	if floor > base.Version {
		out.Full = true
		return out, nil
	}
	keys := map[string]map[string]bool{}
	count := 0
	err := nodePolicyRows(ctx, q, `SELECT entity, resource_key FROM node_policy_changes WHERE version > $1 AND version <= $2`, func(r *sql.Rows) error {
		var entity, key string
		if err := r.Scan(&entity, &key); err != nil {
			return err
		}
		if keys[entity] == nil {
			keys[entity] = map[string]bool{}
		}
		if !keys[entity][key] {
			keys[entity][key] = true
			count++
		}
		return nil
	}, base.Version, out.Version)
	if err != nil {
		return nodepolicy.FactChanges{}, err
	}
	if count > maxIncrementalKeys || len(keys["full"]) > 0 {
		out.Full = true
		return out, nil
	}
	list := func(set map[string]bool, uuidsOnly bool) []string {
		out := make([]string, 0, len(set))
		for k := range set {
			// A key that is not a UUID cannot match an id column (and the
			// cast would fail); nothing keyed by it can exist.
			if !uuidsOnly || uuidKey.MatchString(k) {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	principals := keys["principal"]
	if principals == nil {
		principals = map[string]bool{}
	}
	// DIDs (links, legacy flags) resolve to the users that carry them in this
	// snapshot; a user whose DID itself changed is recorded by its own id.
	if dids := list(keys["did"], false); len(dids) > 0 {
		if err := nodePolicyRows(ctx, q, `SELECT id::text FROM users WHERE external_id = ANY($1)`, func(r *sql.Rows) error {
			var id string
			if err := r.Scan(&id); err != nil {
				return err
			}
			principals[id] = true
			return nil
		}, dids); err != nil {
			return nodepolicy.FactChanges{}, err
		}
	}
	groups := keys["group"]
	if groups == nil {
		groups = map[string]bool{}
	}
	// A moved contract changes the embedded address of every group holding a
	// grant on it now; a grant removed since base recorded its own group.
	if ids := list(keys["contract_id"], true); len(ids) > 0 {
		if err := nodePolicyRows(ctx, q, `SELECT DISTINCT group_id::text FROM contract_grants WHERE contract_id = ANY($1::uuid[])`, func(r *sql.Rows) error {
			var id string
			if err := r.Scan(&id); err != nil {
				return err
			}
			groups[id] = true
			return nil
		}, ids); err != nil {
			return nodepolicy.FactChanges{}, err
		}
	}
	out.Principals = list(principals, true)
	out.Groups = list(groups, true)
	out.Contracts = list(keys["contract"], false)
	out.PolicyOrgs = list(keys["policy"], true)
	out.Sanctions = list(keys["sanctions"], false)
	var current nodepolicy.Snapshot
	scope := factScope{principals: out.Principals, groups: out.Groups, contracts: out.Contracts, policyOrgs: out.PolicyOrgs, sanctions: out.Sanctions}
	if err := exportNodeFactScope(ctx, q, scope, &current); err != nil {
		return nodepolicy.FactChanges{}, err
	}
	out.Current = nodepolicy.FactSet{Principals: current.Principals, Groups: current.Groups, Contracts: current.Contracts, Policies: current.Policies, Sanctions: current.Sanctions}
	return out, nil
}

func nodePolicyRows(ctx context.Context, q DBTX, query string, scan func(*sql.Rows) error, args ...any) error {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func nodeClaimMask(raw []byte) (uint8, error) {
	var claims []string
	if err := json.Unmarshal(raw, &claims); err != nil {
		return 0, err
	}
	var mask uint8
	for _, claim := range claims {
		switch claim {
		case "admin":
			mask |= nodepolicy.ClaimAdmin | nodepolicy.ClaimDeploy | nodepolicy.ClaimUpgrade
		case "deploy":
			mask |= nodepolicy.ClaimDeploy
		case "upgrade":
			mask |= nodepolicy.ClaimUpgrade
		default:
			return 0, fmt.Errorf("unsupported operational claim in node facts")
		}
	}
	return mask, nil
}
