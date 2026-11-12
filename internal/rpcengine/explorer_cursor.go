package rpcengine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"privacy-proxy/internal/explorerquery"
)

func (e *ExplorerEngine) openExplorerCursor(r *ExplorerOperationResult) error {
	if r.request.cursor == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.request.cursor)
	if err != nil || len(raw) < e.cursor.NonceSize()+e.cursor.Overhead() || len(raw) > 6144 {
		return errExplorer
	}
	plain, err := e.cursor.Open(nil, raw[:e.cursor.NonceSize()], raw[e.cursor.NonceSize():], r.request.digest[:])
	if err != nil {
		return errExplorer
	}
	var cursor explorerCursor
	if json.Unmarshal(plain, &cursor) != nil {
		return errExplorer
	}
	c := r.current
	if cursor.Version != 1 || cursor.Actor != c.OriginalView().ActorID() || cursor.Organization != c.Organization() || cursor.Auth != c.AuthCapture() || cursor.Policy != e.policy || cursor.Query != r.request.digest || cursor.Source != e.metadata.Binding || cursor.Wallet != c.WalletVersion() || cursor.Expires != cursorExpiry(c) || c.OriginalView().RequireLive() != nil {
		return errExplorer
	}
	r.request.query.After = &cursor.After
	r.request.query.Upper = cursor.Upper
	return nil
}
func (e *ExplorerEngine) sealExplorerCursor(r *ExplorerOperationResult, after explorerquery.Position) (string, error) {
	if r.current == nil || r.pass == nil {
		return "", errExplorer
	}
	c := r.current
	upper := r.pass.Upper()
	cursor := explorerCursor{Version: 1, Actor: c.OriginalView().ActorID(), Organization: c.Organization(), Wallet: c.WalletVersion(), Auth: c.AuthCapture(), Policy: e.policy, Query: r.request.digest, Source: e.metadata.Binding, Upper: upper, After: after, Expires: cursorExpiry(c)}
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
