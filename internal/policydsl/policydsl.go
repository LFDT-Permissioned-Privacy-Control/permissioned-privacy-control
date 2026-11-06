// Package policydsl preserves the existing compiler-backed API for legacy
// callers. Native-only consumers import policycore directly; this compatibility
// package deliberately includes the separately maintained optional EVM backend.
package policydsl

import (
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybackend/evm"
	"privacy-proxy/internal/policycore"
)

type (
	Policy            = policycore.Policy
	Binding           = policycore.Binding
	FrameRule         = policycore.FrameRule
	ArgConstraint     = policycore.ArgConstraint
	AddressMatch      = policycore.AddressMatch
	AddressSource     = policycore.AddressSource
	CallType          = policycore.CallType
	DeployerException = policycore.DeployerException
	RecordPartyMatch  = policycore.RecordPartyMatch
	Catalog           = policycore.Catalog
	ContractInfo      = policycore.ContractInfo
	Validated         = policycore.Validated
	Frame             = policycore.Frame
	Context           = policycore.Context
	Decision          = policycore.Decision
	DenialCode        = policycore.DenialCode
	ValidationError   = policycore.ValidationError
	LegacySnapshot    = policycore.LegacySnapshot
	LegacyProxyPair   = policycore.LegacyProxyPair
	LegacyGroup       = policycore.LegacyGroup
	LegacyGrant       = policycore.LegacyGrant
	LegacyFunction    = policycore.LegacyFunction
	LegacyParamRule   = policycore.LegacyParamRule
	LegacyImportIssue = policycore.LegacyImportIssue
	LegacyImportError = policycore.LegacyImportError
	Artifact          = evm.Artifact
	ArtifactSet       = evm.ArtifactSet
	Compiler          = evm.Compiler
	CompilerSettings  = evm.CompilerSettings
	EVMEvaluator      = evm.EVMEvaluator
)

const (
	APIVersion                   = policycore.APIVersion
	Kind                         = policycore.Kind
	NestedCallsRequireOwnRule    = policycore.NestedCallsRequireOwnRule
	CallTypeCall                 = policycore.CallTypeCall
	CallTypeStaticCall           = policycore.CallTypeStaticCall
	CallTypeDelegateCall         = policycore.CallTypeDelegateCall
	CallTypeCallCode             = policycore.CallTypeCallCode
	CallTypeCreate               = policycore.CallTypeCreate
	CallTypeCreate2              = policycore.CallTypeCreate2
	AddressSourceSigner          = policycore.AddressSourceSigner
	AddressSourcePrincipalLinked = policycore.AddressSourcePrincipalLinked
	AddressSourceLiteral         = policycore.AddressSourceLiteral
	ClaimAdmin                   = policycore.ClaimAdmin
	ClaimDeploy                  = policycore.ClaimDeploy
	ClaimUpgrade                 = policycore.ClaimUpgrade
	CodeUnknown                  = policycore.CodeUnknown
	CodeEOA                      = policycore.CodeEOA
	CodeContract                 = policycore.CodeContract
	CodePrecompile               = policycore.CodePrecompile
	RecordReadGas                = policycore.RecordReadGas
	MaxRecordIDBytes             = policycore.MaxRecordIDBytes
	MaxRecordOutputs             = policycore.MaxRecordOutputs
	DenialNoMatchingRule         = policycore.DenialNoMatchingRule
	DenialArgumentConstraint     = policycore.DenialArgumentConstraint
	DenialMalformedCalldata      = policycore.DenialMalformedCalldata
	DenialNoFrames               = policycore.DenialNoFrames
	DenialInvalidContext         = policycore.DenialInvalidContext
	DenialOwnership              = policycore.DenialOwnership
	DenialValue                  = policycore.DenialValue
	DenialDepth                  = policycore.DenialDepth
	DenialUnsupportedCreate      = policycore.DenialUnsupportedCreate
	DenialCaller                 = policycore.DenialCaller
	DenialOperationalClaim       = policycore.DenialOperationalClaim
	DenialInvalidFacts           = policycore.DenialInvalidFacts
	OptimizerRuns                = evm.OptimizerRuns
	EVMVersion                   = evm.EVMVersion
	MaxRuntimeBytecode           = evm.MaxRuntimeBytecode
	ArtifactSetBuildTimeout      = evm.ArtifactSetBuildTimeout
	SolidityVersion              = evm.SolidityVersion
	ContractName                 = evm.ContractName
	CheckSignature               = evm.CheckSignature
	CheckFrameSignature          = evm.CheckFrameSignature
)

var ErrPolicyTooLarge = evm.ErrPolicyTooLarge

func Parse(data []byte) (*Policy, error) { return policycore.Parse(data) }
func Validate(policy *Policy, catalog Catalog) (*Validated, error) {
	return policycore.Validate(policy, catalog)
}
func ImportLegacy(snapshot LegacySnapshot, catalog Catalog) (*Policy, error) {
	return policycore.ImportLegacy(snapshot, catalog)
}
func NormalizeProxyPairs(pairs []LegacyProxyPair) ([]LegacyProxyPair, error) {
	return policycore.NormalizeProxyPairs(pairs)
}
func ApplyProxyPairs(policy *Policy, pairs []LegacyProxyPair) (*Policy, error) {
	return policycore.ApplyProxyPairs(policy, pairs)
}
func CanonicalDigest(policy *Policy) (string, error)            { return policycore.CanonicalDigest(policy) }
func ABIDigest(abiText string) string                           { return policycore.ABIDigest(abiText) }
func NewCompiler() *Compiler                                    { return evm.NewCompiler() }
func NewEVMEvaluator(artifact *Artifact) (*EVMEvaluator, error) { return evm.NewEVMEvaluator(artifact) }
func DecodeArtifactSet(raw []byte) (*ArtifactSet, error)        { return evm.DecodeArtifactSet(raw) }
func GenerateSolidity(validated *Validated) (string, error)     { return evm.GenerateSolidity(validated) }
func CallTypeOrdinal(kind CallType) (uint8, bool)               { return evm.CallTypeOrdinal(kind) }
func GroupID(group string) common.Hash                          { return evm.GroupID(group) }
func OrgID(org string) common.Hash                              { return evm.OrgID(org) }
