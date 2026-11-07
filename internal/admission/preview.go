package admission

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/transactioninput"
)

// PreviewRequest names an operational record scope. Naming an actor never
// establishes membership, wallet ownership or permission to submit this tx.
type PreviewRequest struct {
	OriginatorActorID string `json:"originatorActorId"`
	SignedTransaction string `json:"signedTransaction"`
	Renewal           bool   `json:"renewal" optional:"true"`
}

func (s *Service) FinancialPreview(ctx context.Context, token, org string, req PreviewRequest) (*Response, error) {
	v, err := s.adminView(token, org, false)
	if err != nil {
		return nil, err
	}
	if !validActor(req.OriginatorActorID) {
		return nil, ErrInvalid
	}
	tx, err := transactioninput.DecodeRaw(req.SignedTransaction, s.network.ChainID, transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		return nil, ErrInvalid
	}
	to, hasTo := tx.Destination()
	if !hasTo {
		return nil, ErrInvalid
	}
	quotes, err := s.captureQuotes(ctx)
	if err != nil {
		return nil, err
	}
	scope := Scope{Network: s.networkKey, State: s.state, Organization: org, Actor: req.OriginatorActorID, Hash: tx.Hash()}
	var result *compliance.CheckResult
	var at time.Time
	used := map[string]Quote{}
	err = s.store.WithReadOnly(ctx, scope, func(read ReadTx) error {
		if err := s.admin(v, org, false); err != nil {
			return err
		}
		at = s.clock().UTC()
		request := s.newRequestStore(scope, at, quotes, read, nil)
		checker, err := compliance.NewSourceChecker(request, compliance.SourceCheckOptions{OrganizationID: org, ActorID: scope.Actor, Currency: request.org.policy.Spec.Settings.Currency, DecisionAt: at, PriceMaxAge: time.Duration(request.org.policy.PriceMaxAgeSeconds) * time.Second})
		if err != nil {
			return ErrInvalid
		}
		result, err = checker.CheckPreview(ctx, request.checkRequest(tx.Hash().Hex(), AddressString(tx.Signer()), AddressString(to), "0x"+hex.EncodeToString(tx.Input()), "0x"+tx.Value().Text(16), req.Renewal))
		if err != nil {
			return err
		}
		if result == nil {
			return ErrUnavailable
		}
		used = request.used
		return s.checkTime(v, org, at, used, nil)
	})
	if err != nil {
		return nil, err
	}
	coverage := "not_detected"
	if result.TransferInfo != nil {
		coverage = "disabled"
		if s.orgs[org].policy.Spec.Settings.Enabled {
			coverage = "root_transfer"
		}
	}
	return response(struct {
		Preview      bool      `json:"preview"`
		Coverage     string    `json:"coverage"`
		Allowed      bool      `json:"allowed"`
		Monitored    bool      `json:"monitored"`
		Reason       string    `json:"reason"`
		RecordID     string    `json:"recordId,omitempty"`
		SourceDigest string    `json:"sourceDigest"`
		DecisionAt   time.Time `json:"decisionAt"`
	}{true, coverage, result.Allowed, result.Monitored, result.Reason, result.TravelRuleRecordID, s.complianceDigest.String(), at}, func() error {
		if err := s.admin(v, org, false); err != nil {
			return err
		}
		return s.checkTime(v, org, at, used, nil)
	})
}

type EventDTO struct {
	ID              int64     `json:"id"`
	TransactionHash string    `json:"transactionHash"`
	ActorID         string    `json:"actorId"`
	Kind            string    `json:"kind"`
	Coverage        string    `json:"coverage"`
	From            string    `json:"from,omitempty"`
	To              string    `json:"to,omitempty"`
	Token           string    `json:"token,omitempty"`
	AmountWei       *string   `json:"amountWei,omitempty"`
	AmountFiat      *float64  `json:"amountFiat,omitempty"`
	ThresholdFiat   *float64  `json:"thresholdFiat,omitempty"`
	Currency        *string   `json:"currency,omitempty"`
	Decision        string    `json:"decision"`
	Monitored       bool      `json:"monitored"`
	Reason          string    `json:"reason,omitempty"`
	RecordID        *string   `json:"recordId,omitempty"`
	DecisionAt      time.Time `json:"decisionAt"`
	PolicyDigest    string    `json:"policyDigest"`
	Quote           *Quote    `json:"quote,omitempty"`
}

func eventDTO(e Event) EventDTO {
	out := EventDTO{ID: e.ID, TransactionHash: e.Scope.Hash.Hex(), ActorID: e.Scope.Actor, Kind: e.Kind, Coverage: e.Coverage, AmountWei: e.AmountWei, AmountFiat: e.AmountFiat, ThresholdFiat: e.Threshold, Currency: e.Currency, Decision: e.Decision, Monitored: e.Monitored, Reason: e.Reason, RecordID: e.RecordID, DecisionAt: e.DecisionAt, PolicyDigest: e.PolicyDigest.String(), Quote: e.Quote}
	if e.From != nil {
		out.From = AddressString(*e.From)
	}
	if e.To != nil {
		out.To = AddressString(*e.To)
	}
	if e.Token != nil {
		out.Token = AddressString(*e.Token)
	}
	return out
}
func (s *Service) ListEvents(ctx context.Context, token, org string, opts ListOptions) (*Response, error) {
	v, err := s.adminView(token, org, false)
	if err != nil {
		return nil, err
	}
	limit, cursor, err := s.page(v, org, "events", opts)
	if err != nil {
		return nil, err
	}
	position := EventPosition{At: cursor.At}
	if !cursor.At.IsZero() {
		id, err := strconv.ParseInt(cursor.ID, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != cursor.ID {
			return nil, ErrConflict
		}
		position.ID = id
	}
	rows, err := s.store.ListEvents(ctx, s.networkKey, s.state, org, position, limit+1)
	if err != nil {
		return nil, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]EventDTO, 0, len(rows))
	for _, row := range rows {
		if !row.Valid() || row.Scope.Organization != org || row.Scope.Network != s.networkKey {
			return nil, ErrUnavailable
		}
		out = append(out, eventDTO(row))
	}
	next := ""
	if more && len(rows) > 0 {
		last := rows[len(rows)-1]
		next, err = s.nextCursor(v, cursor, Position{last.DecisionAt, strconv.FormatInt(last.ID, 10)})
		if err != nil {
			return nil, err
		}
	}
	return response(struct {
		Events     []EventDTO `json:"events"`
		NextCursor string     `json:"nextCursor,omitempty"`
	}{out, next}, func() error { return s.admin(v, org, false) })
}
