package rbac

import "privacy-proxy/internal/readprivacy"

type TxSurface = readprivacy.TxSurface
type TxEnvelopeFacts = readprivacy.TxEnvelopeFacts

const (
	TxSurfaceTransaction = readprivacy.TxSurfaceTransaction
	TxSurfaceReceipt     = readprivacy.TxSurfaceReceipt
	TxSurfaceBlockEntry  = readprivacy.TxSurfaceBlockEntry
)

func DecideTxEnvelope(profile ReadProfile, facts TxEnvelopeFacts) bool {
	return readprivacy.DecideTxEnvelope(profile, facts)
}
