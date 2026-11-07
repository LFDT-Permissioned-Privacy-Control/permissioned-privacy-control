package identityhttp

import (
	"net/http"

	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
)

type AccessDTO struct {
	AccessToken      string        `json:"accessToken"`
	TokenType        string        `json:"tokenType"`
	ActorID          string        `json:"actorId"`
	PrincipalKind    identity.Kind `json:"principalKind"`
	Provider         string        `json:"provider"`
	SourceProfile    string        `json:"sourceProfile"`
	ExpiresAt        int64         `json:"expiresAt"`
	BrowserSessionID string        `json:"browserSessionId,omitempty"`
}
type browserResult interface {
	Metadata() b.ResultMetadata
	Credentials() (string, string, error)
	SessionInfo() (b.BrowserSession, error)
	RequireDeliverable() error
}

func (h *Handler) dto(meta b.ResultMetadata, access string, kind identity.Kind) (AccessDTO, error) {
	sourceKind := identity.AzureHuman
	if kind == identity.Service {
		sourceKind = identity.AzureService
	}
	if meta.Kind != kind || !identity.ValidActorID(meta.ActorID) || h.kinds[meta.ProfileID] != sourceKind || len(access) == 0 || len(access) > identity.DefaultLimits().MaxCompactAccessBytes {
		return AccessDTO{}, b.ErrUnavailable
	}
	return AccessDTO{AccessToken: access, TokenType: "Bearer", ActorID: meta.ActorID, PrincipalKind: kind, Provider: "azure", SourceProfile: meta.ProfileID, ExpiresAt: meta.ExpiresAt.Unix()}, nil
}
func (h *Handler) publishBrowser(w http.ResponseWriter, r *http.Request, c requestCookies, result browserResult) {
	access, renewal, err := result.Credentials()
	if err != nil {
		failService(w, err)
		return
	}
	session, err := result.SessionInfo()
	if err != nil {
		failService(w, err)
		return
	}
	dto, err := h.dto(result.Metadata(), access, identity.Human)
	if err != nil || !b.ValidUUID(session.ID) || session.ActorID != dto.ActorID || len(renewal) == 0 || len(renewal) > 3500 {
		failService(w, b.ErrUnavailable)
		return
	}
	dto.BrowserSessionID = session.ID
	at, err := h.now()
	if err != nil {
		failService(w, err)
		return
	}
	recipientCookie, err := cookie(RecipientCookie, c.recipient, session.AbsoluteExpiresAt, at)
	if err != nil {
		failService(w, err)
		return
	}
	refreshCookie, err := cookie(RenewalCookie, renewal, session.AbsoluteExpiresAt, at)
	if err != nil {
		failService(w, err)
		return
	}
	publish(w, r, dto, []string{recipientCookie, refreshCookie}, func() error {
		if err := result.RequireDeliverable(); err != nil {
			return err
		}
		_, err := result.SessionInfo()
		return err
	})
}
func (h *Handler) start(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		ProfileID string `json:"profileId"`
	}
	if decode(r, &request, 2<<10) != nil || h.kinds[request.ProfileID] != identity.AzureHuman {
		failService(w, b.ErrInvalid)
		return
	}
	secret := c.recipient
	var err error
	if secret == "" {
		secret, err = newRecipient()
		if err != nil {
			failService(w, err)
			return
		}
	}
	binding, err := recipient(secret)
	if err != nil {
		failService(w, err)
		return
	}
	result, err := h.service.BeginAzure(r.Context(), request.ProfileID, binding)
	if err != nil {
		failService(w, err)
		return
	}
	at, err := h.now()
	if err != nil {
		failService(w, err)
		return
	}
	header, err := cookie(RecipientCookie, secret, at.Add(b.FamilyLifetime), at)
	if err != nil {
		failService(w, err)
		return
	}
	publish(w, r, struct {
		AuthorizationURL string `json:"authorizationUrl"`
		ExpiresAt        int64  `json:"expiresAt"`
	}{result.AuthorizationURL, result.ExpiresAt.Unix()}, []string{header}, func() error {
		current, err := h.now()
		if err != nil {
			return err
		}
		if current.Before(result.ExpiresAt.Add(-b.PendingLifetime)) {
			return b.ErrUnavailable
		}
		return live(r.Context(), current, result.ExpiresAt)
	})
}
func (h *Handler) complete(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}
	if decode(r, &request, 12<<10) != nil {
		failService(w, b.ErrInvalid)
		return
	}
	if c.recipient == "" {
		failService(w, b.ErrUnauthorized)
		return
	}
	binding, err := recipient(c.recipient)
	if err != nil {
		failService(w, err)
		return
	}
	result, err := h.service.CompleteAzure(r.Context(), request.State, request.Code, binding)
	if err != nil {
		failService(w, err)
		return
	}
	h.publishBrowser(w, r, c, result)
}
func (h *Handler) renew(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		Mode              string  `json:"mode"`
		ExpectedActorID   *string `json:"expectedActorId,omitempty" optional:"true"`
		ExpectedSessionID *string `json:"expectedSessionId,omitempty" optional:"true"`
	}
	if decode(r, &request, 2<<10) != nil {
		failService(w, b.ErrInvalid)
		return
	}
	if request.Mode == "bootstrap" {
		if request.ExpectedActorID != nil || request.ExpectedSessionID != nil {
			failService(w, b.ErrInvalid)
			return
		}
	} else if request.Mode == "renew" {
		if request.ExpectedActorID == nil || request.ExpectedSessionID == nil || !(b.ExpectedSession{ActorID: *request.ExpectedActorID, SessionID: *request.ExpectedSessionID}).Valid() {
			failService(w, b.ErrInvalid)
			return
		}
	} else {
		failService(w, b.ErrInvalid)
		return
	}
	if c.recipient == "" || c.renewal == "" {
		failService(w, b.ErrUnauthorized)
		return
	}
	binding, err := recipient(c.recipient)
	if err != nil {
		failService(w, err)
		return
	}
	var result *b.CommittedRenewal
	if request.Mode == "bootstrap" {
		result, err = h.service.RenewAzure(r.Context(), c.renewal, binding)
	} else {
		result, err = h.service.RenewAzureForSession(r.Context(), c.renewal, binding, b.ExpectedSession{ActorID: *request.ExpectedActorID, SessionID: *request.ExpectedSessionID})
	}
	if err != nil {
		failService(w, err)
		return
	}
	h.publishBrowser(w, r, c, result)
}
func (h *Handler) logout(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		ExpectedActorID   string `json:"expectedActorId"`
		ExpectedSessionID string `json:"expectedSessionId"`
	}
	if decode(r, &request, 2<<10) != nil {
		failService(w, b.ErrInvalid)
		return
	}
	expected := b.ExpectedSession{ActorID: request.ExpectedActorID, SessionID: request.ExpectedSessionID}
	if !expected.Valid() {
		failService(w, b.ErrInvalid)
		return
	}
	if c.recipient == "" || c.renewal == "" {
		failService(w, b.ErrUnauthorized)
		return
	}
	binding, err := recipient(c.recipient)
	if err != nil {
		failService(w, err)
		return
	}
	if err := h.service.RevokeForSession(r.Context(), c.renewal, binding, expected); err != nil {
		failService(w, err)
		return
	}
	if r.Context().Err() != nil {
		failService(w, b.ErrUnavailable)
		return
	}
	w.Header().Add("Set-Cookie", expiredCookie(RecipientCookie))
	w.Header().Add("Set-Cookie", expiredCookie(RenewalCookie))
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProfileID           string `json:"profileId"`
		UpstreamAccessToken string `json:"upstreamAccessToken"`
	}
	if decode(r, &request, 40<<10) != nil || h.kinds[request.ProfileID] != identity.AzureService {
		failService(w, b.ErrInvalid)
		return
	}
	result, err := h.service.ExchangeAzureService(r.Context(), request.ProfileID, request.UpstreamAccessToken)
	if err != nil {
		failService(w, err)
		return
	}
	access, err := result.Credentials()
	if err != nil {
		failService(w, err)
		return
	}
	dto, err := h.dto(result.Metadata(), access, identity.Service)
	if err != nil {
		failService(w, err)
		return
	}
	publish(w, r, dto, nil, result.RequireDeliverable)
}
