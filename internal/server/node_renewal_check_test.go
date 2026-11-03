package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// renewalStore is the RBAC store the renewal re-check reads.
type renewalStore struct {
	rbac.Store // unexpected calls panic
	user       *rbac.User
	orgs       map[string]bool
	memberOf   string
	linked     []string
	methods    []string
	owner      string // the target contract's organisation ("" = unregistered)
	err        error
}

func (s *renewalStore) GetUserByExternalID(_ context.Context, did string) (*rbac.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.user != nil && s.user.ExternalID == did {
		return s.user, nil
	}
	return nil, nil
}
func (s *renewalStore) GetOrganization(_ context.Context, id string) (*rbac.Organization, error) {
	if s.orgs[id] {
		return &rbac.Organization{ID: id}, nil
	}
	return nil, nil
}
func (s *renewalStore) GetContractOwnerOrgID(context.Context, string) (string, error) {
	return s.owner, nil
}
func (s *renewalStore) ListUserMembershipsWithDetails(context.Context, string) ([]*rbac.MembershipWithDetails, error) {
	if s.memberOf == "" {
		return nil, nil
	}
	return []*rbac.MembershipWithDetails{{Group: &rbac.Group{ID: "group-a", OrgID: s.memberOf}}}, nil
}
func (s *renewalStore) ListActiveUserMembershipsWithDetails(ctx context.Context, userID string) ([]*rbac.MembershipWithDetails, error) {
	return s.ListUserMembershipsWithDetails(ctx, userID)
}
func (s *renewalStore) GetCachedPermissions(_ context.Context, user, org string) (*rbac.EffectivePermissions, error) {
	return &rbac.EffectivePermissions{UserID: user, OrgID: org, AllowedMethods: s.methods, ContractAccess: map[string]rbac.ContractAccess{}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (s *renewalStore) GetLinkedEthAddresses(context.Context, string) ([]string, error) {
	return s.linked, nil
}
func (s *renewalStore) IsOrgAdmin(context.Context, string) (bool, []string, error) {
	return false, nil, nil
}

// G16: the renewal re-runs every admission check against current state —
// a banned, unverified, deleted or no-longer-member principal, a deleted
// organisation, a method no longer allowed, a target contract of another
// organisation, an unlinked signer, or visibleTo under the strict profile
// stops renewal with that reason; a store error is retried, never decided.
func TestRenewalRecheckRerunsEveryAdmissionCheck(t *testing.T) {
	key, _ := crypto.GenerateKey()
	tx := signTransfer(t, key, 0)
	principal, org := uuid.New(), uuid.New()
	baseline := func() *renewalStore {
		return &renewalStore{user: &rbac.User{ID: principal.String(), ExternalID: "did:test:p", KYC: true}, orgs: map[string]bool{org.String(): true}, memberOf: org.String(),
			linked: []string{tx.signer}, methods: []string{"eth_sendTransaction"}}
	}
	row := db.TrackedTransaction{Hash: hashBytes(t, tx.hash), PrincipalID: principal, OrgID: org, Signer: hashBytes(t, tx.signer)}
	raw := hashBytes(t, tx.raw)
	for _, test := range []struct {
		name   string
		mutate func(*renewalStore, *db.TrackedTransaction, *admissionRechecker)
		want   int16
		err    bool
	}{
		{"allowed", func(*renewalStore, *db.TrackedTransaction, *admissionRechecker) {}, 0, false},
		{"principal_deleted", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.user = nil }, db.TrackReasonPrincipalDeleted, false},
		{"principal_replaced", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.user.ID = uuid.NewString() }, db.TrackReasonPrincipalDeleted, false},
		{"banned", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.user.Banned = true }, db.TrackReasonPrincipalBanned, false},
		{"kyc_missing", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.user.KYC = false }, db.TrackReasonKYCMissing, false},
		{"org_deleted", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.orgs = map[string]bool{} }, db.TrackReasonOrganizationDeleted, false},
		{"not_member", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.memberOf = uuid.NewString() }, db.TrackReasonNotMember, false},
		{"method_removed", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) {
			s.methods = []string{"eth_call"}
		}, db.TrackReasonMethodNotAllowed, false},
		{"target_of_another_org", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.owner = uuid.NewString() }, db.TrackReasonMethodNotAllowed, false},
		{"signer_unlinked", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) { s.linked = nil }, db.TrackReasonSenderUnlinked, false},
		{"raw_signed_by_another_key", func(_ *renewalStore, r *db.TrackedTransaction, _ *admissionRechecker) { r.Signer = make([]byte, 20) }, db.TrackReasonSenderUnlinked, false},
		{"strict_profile_visible_to", func(_ *renewalStore, r *db.TrackedTransaction, c *admissionRechecker) {
			r.VisibleTo, c.strictVisibleTo = []string{"did:test:viewer"}, true
		}, db.TrackReasonVisibilityNotAllowed, false},
		{"store_error", func(s *renewalStore, _ *db.TrackedTransaction, _ *admissionRechecker) {
			s.err = errors.New("database unavailable")
		}, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, r := baseline(), row
			checker := &admissionRechecker{network: keeperNetwork}
			test.mutate(store, &r, checker)
			checker.ac = rbac.NewAccessController(store, time.Minute)
			defer checker.ac.Stop()
			refusal, _, err := checker.Recheck(context.Background(), r, raw, "did:test:p", uuid.New())
			if (err != nil) != test.err || refusal != test.want {
				t.Fatalf("refusal %s (%d), err %v; want %s (%d), error %v", db.TrackReasonName(refusal), refusal, err, db.TrackReasonName(test.want), test.want, test.err)
			}
		})
	}
	if refusal, _, err := (&admissionRechecker{ac: rbac.NewAccessController(baseline(), time.Minute)}).Recheck(context.Background(), row, raw, "", uuid.New()); err != nil || refusal != db.TrackReasonPrincipalDeleted {
		t.Fatalf("a principal without a DID: %d %v", refusal, err)
	}
}
