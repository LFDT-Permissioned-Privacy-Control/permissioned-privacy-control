package identitybroker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"

	"privacy-proxy/internal/identitybroker/privado"
	"privacy-proxy/internal/strictjson"
)

// These small canonical payloads authenticate continuity, never role facts or a
// serialized verifier result. Every omitted row field is in the corresponding
// ordered AEAD additional data below.
type providerPlan struct {
	IdentityDigest     string `json:"identityDigest"`
	ProfilePlanDigest  string `json:"profilePlanDigest"`
	NetworkPlanDigest  string `json:"networkPlanDigest"`
	DocumentPlanDigest string `json:"documentPlanDigest"`
}

func plan(m privado.Metadata) providerPlan {
	return providerPlan{m.IdentityDigest, m.ProfilePlanDigest, m.NetworkPlanDigest, m.DocumentPlanDigest}
}
func (p providerPlan) metadata() privado.Metadata {
	return privado.Metadata{IdentityDigest: p.IdentityDigest, ProfilePlanDigest: p.ProfilePlanDigest, NetworkPlanDigest: p.NetworkPlanDigest, DocumentPlanDigest: p.DocumentPlanDigest}
}

type privadoChallengePayload struct {
	Version          uint8        `json:"version"`
	Nonce            string       `json:"nonce"`
	SourceAuthDigest string       `json:"sourceAuthDigest"`
	Provider         providerPlan `json:"provider"`
	CallbackDigest   string       `json:"callbackDigest"`
}
type privadoFamilyPayload struct {
	Version          uint8        `json:"version"`
	SourceAuthDigest string       `json:"sourceAuthDigest"`
	Provider         providerPlan `json:"provider"`
}

func canonicalPrivadoDecode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 2020 || !utf8.Valid(raw) {
		return ErrUnauthorized
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, e := strictjson.ReadValue(d, 0, 4)
	if e != nil {
		return ErrUnauthorized
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrUnauthorized
	}
	var count func(any) int
	count = func(v any) int {
		n := 1
		switch x := v.(type) {
		case map[string]any:
			for _, v := range x {
				n += count(v)
			}
		case []any:
			for _, v := range x {
				n += count(v)
			}
		}
		return n
	}
	if count(value) > 64 || strictjson.ExactDecode(value, out) != nil {
		return ErrUnauthorized
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(canonical, raw) {
		return ErrUnauthorized
	}
	return nil
}
func decodePrivadoChallenge(raw []byte) (privadoChallengePayload, [32]byte, error) {
	var p privadoChallengePayload
	var nonce [32]byte
	if canonicalPrivadoDecode(raw, &p) != nil || p.Version != 1 || !validProviderMetadata(p.Provider.metadata()) {
		return p, nonce, ErrUnauthorized
	}
	if _, e := ParseDigest(p.SourceAuthDigest); e != nil {
		return p, nonce, ErrUnauthorized
	}
	if _, e := ParseDigest(p.CallbackDigest); e != nil {
		return p, nonce, ErrUnauthorized
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(p.Nonce)
	if e != nil || len(p.Nonce) != 43 || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != p.Nonce {
		return p, nonce, ErrUnauthorized
	}
	copy(nonce[:], b)
	if nonce == ([32]byte{}) {
		return p, nonce, ErrUnauthorized
	}
	return p, nonce, nil
}
func decodePrivadoFamily(raw []byte) (privadoFamilyPayload, error) {
	var p privadoFamilyPayload
	if canonicalPrivadoDecode(raw, &p) != nil || p.Version != 1 || !validProviderMetadata(p.Provider.metadata()) {
		return p, ErrUnauthorized
	}
	if _, e := ParseDigest(p.SourceAuthDigest); e != nil {
		return p, ErrUnauthorized
	}
	return p, nil
}
func privadoChallengeAAD(p PrivadoChallengeRecord) []byte {
	gen := []byte{}
	handle := []byte{}
	if p.CurrentGeneration != nil {
		gen = []byte(strconv.FormatInt(*p.CurrentGeneration, 10))
	}
	if p.CurrentHandleHash != nil {
		handle = p.CurrentHandleHash[:]
	}
	return Pack("ops.broker.privado.challenge/v1", p.Scope.Namespace[:], []byte(p.Scope.State.RecoveryEpoch), []byte(p.ID), []byte(FamilyPrivado), []byte(p.ProfileID), []byte(p.ProfileDigest), p.Recipient[:], []byte(p.Mode), []byte(p.ExpectedActorID), []byte(p.FamilyID), gen, handle, []byte(p.EncryptionKeyID), []byte(strconv.FormatInt(p.CreatedAt.Unix(), 10)), []byte(strconv.FormatInt(p.ExpiresAt.Unix(), 10)))
}
func privadoFamilyAAD(f Family) []byte {
	return Pack("ops.broker.privado.family/v1", f.Scope.Namespace[:], []byte(f.Scope.State.RecoveryEpoch), []byte(f.ID), []byte(f.RequestID), []byte(FamilyPrivado), []byte(f.Actor), []byte(f.Authority), []byte(f.Subject), []byte(f.Kind), []byte(f.ProfileID), []byte(f.ProfileDigest), f.Recipient[:], []byte(strconv.FormatInt(f.Generation, 10)), f.CurrentHandleHash[:], []byte(f.EncryptionKeyID), []byte(strconv.FormatInt(f.CreatedAt.UnixMicro(), 10)), []byte(strconv.FormatInt(f.AbsoluteExpiresAt.UnixMicro(), 10)), []byte(strconv.FormatInt(f.LastRotatedAt.UnixMicro(), 10)))
}
func privadoOfferAAD(p PrivadoOfferRecord) []byte {
	return Pack("ops.broker.privado.offer/v1", p.Scope.Namespace[:], []byte(p.Scope.State.RecoveryEpoch), []byte(p.RequestID), p.ContextDigest[:], p.ProofDigest[:], []byte(p.HolderDID), []byte(p.ActorID), []byte(p.Network), []byte(p.ProfileID), []byte(p.ProfileDigest), []byte(p.SourceAuthDigest), []byte(p.Provider.IdentityDigest), []byte(p.Provider.ProfilePlanDigest), []byte(p.Provider.NetworkPlanDigest), []byte(p.Provider.DocumentPlanDigest), []byte(strconv.FormatInt(p.ClaimsAsOf, 10)), []byte(strconv.FormatInt(p.NotAfter, 10)), []byte(strconv.FormatInt(p.VerifiedAt, 10)), []byte(p.EncryptionKeyID))
}
