package admissionsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
)

// CreationObserverStatus is an offline operator read. It exposes no policies,
// credentials or permission verdict and cannot make an observer ready.
func CreationObserverStatus(ctx context.Context, dsn string, binding a.NetworkBinding) (f.ObserverState, error) {
	var out f.ObserverState
	key, genesis, err := bindingValues(binding)
	if err != nil {
		return out, err
	}
	err = offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if err := verifyBinding(ctx, tx, key, binding, genesis); err != nil {
			return err
		}
		var err error
		out, _, err = scanObserver(tx.QueryRow(ctx, `SELECT `+observerStateColumns+` `+observerStateJoin, key[:]), f.Digest(key))
		return err
	})
	return out, err
}
