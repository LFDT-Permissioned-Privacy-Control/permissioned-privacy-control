// Package historyfacts binds current read facts to one original verified
// request. Operational adapters supply facts; they never supply permissions.
package historyfacts

import (
	"context"
	"time"

	"privacy-proxy/internal/admissionsharedata"
)

var (
	ErrInvalid     = admissionsharedata.ErrInvalid
	ErrUnavailable = admissionsharedata.ErrUnavailable
	ErrTooBroad    = admissionsharedata.ErrTooBroad
)

const MaxOperationTime = admissionsharedata.MaxOperationTime
const MaxChargedBytes = admissionsharedata.MaxChargedBytes

type Fence = admissionsharedata.Fence

func NewFence(ctx context.Context, timeout time.Duration) (Fence, error) {
	return admissionsharedata.NewFence(ctx, timeout)
}
