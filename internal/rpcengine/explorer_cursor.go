package rpcengine

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"privacy-proxy/internal/explorerquery"
)

var errExplorerCursorInvalid = errors.New("invalid Explorer cursor")

func (e *ExplorerEngine) openExplorerCursor(r *ExplorerOperationResult) error {
	if r.request.cursor == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.request.cursor)
	if err != nil || len(raw) < e.cursor.NonceSize()+e.cursor.Overhead() || len(raw) > 6144 {
		return errExplorerCursorInvalid
	}
	plain, err := e.cursor.Open(nil, raw[:e.cursor.NonceSize()], raw[e.cursor.NonceSize():], r.request.digest[:])
	if err != nil {
		return errExplorerCursorInvalid
	}
	var cursor explorerCursor
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(&cursor) != nil {
		return errExplorerCursorInvalid
	}
	if dec.Decode(new(any)) != io.EOF {
		return errExplorerCursorInvalid
	}
	c := r.current
	if cursor.Version != 2 || cursor.Actor != c.OriginalView().ActorID() || cursor.Organization != c.Organization() || cursor.Auth != c.AuthCapture() || cursor.Query != r.request.digest || cursor.Wallet != c.WalletVersion() || cursor.Expires != cursorExpiry(c) || c.OriginalView().RequireLive() != nil {
		return errExplorerCursorInvalid
	}
	epoch, epochErr := uuid.Parse(cursor.DatasetEpoch)
	if epochErr != nil || epoch == uuid.Nil || epoch.String() != cursor.DatasetEpoch || cursor.Upper == nil || cursor.RunFloor > cursor.Upper.Number || !explorerquery.ValidHash(cursor.Upper.Hash) {
		return errExplorerCursorInvalid
	}
	if cursor.Policy != e.policy || cursor.Source != e.metadata.Binding {
		return errExplorer
	}
	r.request.query.After = &cursor.After
	r.request.query.Upper = cursor.Upper
	r.request.query.DatasetEpoch = cursor.DatasetEpoch
	floor := cursor.RunFloor
	r.request.query.RunFloor = &floor
	return nil
}
func (e *ExplorerEngine) sealExplorerCursor(r *ExplorerOperationResult, after explorerquery.Position) (string, error) {
	if r.current == nil || r.pass == nil {
		return "", errExplorer
	}
	c := r.current
	upper := r.pass.Upper()
	cursor := explorerCursor{Version: 2, Actor: c.OriginalView().ActorID(), Organization: c.Organization(), Wallet: c.WalletVersion(), Auth: c.AuthCapture(), Policy: e.policy, Query: r.request.digest, Source: e.metadata.Binding, Upper: upper, DatasetEpoch: r.pass.DatasetEpoch(), RunFloor: r.pass.RunFloor(), After: after, Expires: cursorExpiry(c)}
	plain, err := json.Marshal(cursor)
	if err != nil || len(plain) > 4096 {
		return "", errExplorer
	}
	nonce := make([]byte, e.cursor.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errExplorer
	}
	sealed := e.cursor.Seal(nonce, nonce, plain, r.request.digest[:])
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
