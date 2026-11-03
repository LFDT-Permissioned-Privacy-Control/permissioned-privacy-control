package server

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/uuid"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

// renewalChecker re-runs every admission check for a pending binding before
// the lease keeper signs another identity for it (plan §4.8.7 step 2).
type renewalChecker interface {
	// Recheck returns a business refusal reason (non-zero: the binding stops
	// renewing) or the travel-rule record the compliance step accepted. An
	// error is an infrastructure failure: nothing is decided, retry later.
	Recheck(ctx context.Context, row db.TrackedTransaction, raw []byte, did string, correlation uuid.UUID) (refusal int16, travelRuleRecord uuid.UUID, err error)
}

// admissionRechecker is the production re-check: the principal, the
// organisation and the membership, the execution admission of the request
// path (method allowlist, contract scope, linked sender; caches bypassed),
// the read profile's visibleTo rule, and compliance in renewal mode (only the
// travel-rule record bound to this transaction counts).
type admissionRechecker struct {
	ac         *rbac.AccessController
	compliance *compliance.Checker
	network    nodepolicy.Network
	// strictVisibleTo: PRIVACY_READ_PROFILE=strict refuses sends with
	// visibleTo, so such a binding is not renewed under it.
	strictVisibleTo bool
}

var errRecheckUnavailable = errors.New("renewal re-check unavailable")

func (c *admissionRechecker) Recheck(ctx context.Context, row db.TrackedTransaction, raw []byte, did string, correlation uuid.UUID) (int16, uuid.UUID, error) {
	if c.ac == nil {
		return 0, uuid.Nil, errRecheckUnavailable
	}
	if did == "" {
		return db.TrackReasonPrincipalDeleted, uuid.Nil, nil
	}
	store := c.ac.Store()
	user, err := store.GetUserByExternalID(ctx, did)
	if err != nil {
		return 0, uuid.Nil, err
	}
	switch {
	case user == nil || user.ID != row.PrincipalID.String():
		return db.TrackReasonPrincipalDeleted, uuid.Nil, nil
	case user.Banned:
		return db.TrackReasonPrincipalBanned, uuid.Nil, nil
	case !user.KYC:
		return db.TrackReasonKYCMissing, uuid.Nil, nil
	}
	orgID := row.OrgID.String()
	org, err := store.GetOrganization(ctx, orgID)
	if err != nil {
		return 0, uuid.Nil, err
	}
	if org == nil {
		return db.TrackReasonOrganizationDeleted, uuid.Nil, nil
	}
	memberships, err := store.ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return 0, uuid.Nil, err
	}
	member := false
	for _, m := range memberships {
		if m != nil && m.Group != nil && m.Group.OrgID == orgID {
			member = true
			break
		}
	}
	if !member {
		return db.TrackReasonNotMember, uuid.Nil, nil
	}
	if c.strictVisibleTo && len(row.VisibleTo) > 0 {
		return db.TrackReasonVisibilityNotAllowed, uuid.Nil, nil
	}
	from, to, data, value, _, err := decodeRawTransaction("0x" + hex.EncodeToString(raw))
	if err != nil {
		return 0, uuid.Nil, err
	}
	signer := "0x" + hex.EncodeToString(row.Signer)
	if !strings.EqualFold(from, signer) {
		return db.TrackReasonSenderUnlinked, uuid.Nil, nil
	}
	admission, err := c.ac.CheckExecutionAdmission(ctx, &rbac.AccessCheckRequest{UserExternalID: did, OrgID: orgID, Method: "eth_sendTransaction", AccessMethod: "eth_sendRawTransaction", Params: buildTxParams(from, to, data, value), TargetAddress: to, BypassCache: true})
	if err != nil {
		return 0, uuid.Nil, err
	}
	if admission == nil {
		return 0, uuid.Nil, errRecheckUnavailable
	}
	if !admission.Allowed {
		switch admission.Reason {
		case rbac.ExecutionSenderNotLinked, rbac.ExecutionSenderRequired:
			return db.TrackReasonSenderUnlinked, uuid.Nil, nil
		default:
			// The method allowlist, the contract's organisation scope, or any
			// other admission rule: never a retry.
			return db.TrackReasonMethodNotAllowed, uuid.Nil, nil
		}
	}
	if admission.UserID != user.ID || admission.OrgID != orgID {
		return db.TrackReasonNotMember, uuid.Nil, nil
	}
	if !strings.EqualFold(admission.Signer, signer) {
		return db.TrackReasonSenderUnlinked, uuid.Nil, nil
	}
	if c.compliance == nil {
		return 0, uuid.Nil, nil
	}
	verdict, err := c.compliance.Check(ctx, &compliance.CheckRequest{OrgID: orgID, UserID: user.ID, From: admission.Signer, To: to, Data: data, Value: value, CorrelationID: correlation.String(),
		Transaction: compliance.TransactionBinding{ChainID: c.network.ChainID, DeploymentID: c.network.DeploymentID, Hash: "0x" + hex.EncodeToString(row.Hash), Renewal: true}})
	if err != nil {
		return 0, uuid.Nil, err
	}
	if verdict == nil {
		return 0, uuid.Nil, errRecheckUnavailable
	}
	if !verdict.Allowed {
		return db.TrackReasonComplianceDenied, uuid.Nil, nil
	}
	record := uuid.Nil
	if verdict.TravelRuleRecordID != "" {
		if record, err = uuid.Parse(verdict.TravelRuleRecordID); err != nil {
			return 0, uuid.Nil, err
		}
	}
	return 0, record, nil
}
