package historyfacts

import (
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/admissionsharedata"
)

const ShareSchemaProfile = admissionsharedata.ShareSchemaProfile
const MaxShareHashes = admissionsharedata.MaxShareHashes

type ShareBinding = admissionsharedata.ShareBinding
type ReaderIdentity = admissionsharedata.ReaderIdentity
type ShareMetadata = admissionsharedata.ShareMetadata
type ShareReader = admissionsharedata.ShareReader
type ShareQuery = admissionsharedata.ShareQuery
type SharePass = admissionsharedata.SharePass

func NewReaderIdentity() *ReaderIdentity { return admissionsharedata.NewReaderIdentity() }
func NormalizeShareQuery(q ShareQuery) (ShareQuery, error) {
	return admissionsharedata.NormalizeShareQuery(q)
}
func NewSharePass(owner *ReaderIdentity, b ShareBinding, q ShareQuery, rows []admission.Share, fence Fence) (*SharePass, error) {
	return admissionsharedata.NewSharePass(owner, b, q, rows, fence)
}
func PrepareShareQuery(hashes []common.Hash, fence Fence, maxBytes int) (ShareQuery, error) {
	return admissionsharedata.PrepareShareQuery(hashes, fence, maxBytes)
}
