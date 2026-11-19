package policycli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/strictjson"
)

type ScenarioContext struct {
	Org               string
	Groups            []string
	Signer            common.Address   `optional:"true"`
	LinkedAddresses   []common.Address `optional:"true"`
	Claims            uint8            `optional:"true"`
	GroupSourceClaims map[string]uint8 `optional:"true"`
}

func (v ScenarioContext) native() policycore.Context {
	return policycore.Context{Org: v.Org, Groups: v.Groups, Signer: v.Signer, LinkedAddresses: v.LinkedAddresses, Claims: v.Claims, GroupSourceClaims: v.GroupSourceClaims}
}

type ScenarioFacts struct {
	CodeKind                   uint8            `optional:"true"`
	UpgradeTargetOrg           string           `optional:"true"`
	GroupClaims                map[string]uint8 `optional:"true"`
	CallerOrg                  string           `optional:"true"`
	CodeOrg                    string           `optional:"true"`
	StorageOrg                 string           `optional:"true"`
	CodeShared                 bool             `optional:"true"`
	CodeAccessible             bool             `optional:"true"`
	StorageShared              bool             `optional:"true"`
	StorageDeployer            bool             `optional:"true"`
	StoragePending             bool             `optional:"true"`
	CreationUnresolved         bool             `optional:"true"`
	CreationNamespace          string           `optional:"true"`
	StorageDeploymentNamespace string           `optional:"true"`
	CodeDeploymentNamespace    string           `optional:"true"`
	StorageRuntimeHasCode      bool             `optional:"true"`
	CallerAddress              common.Address   `optional:"true"`
}

func (v ScenarioFacts) native() policycore.Frame {
	return policycore.Frame{CodeKind: v.CodeKind, UpgradeTargetOrg: v.UpgradeTargetOrg, GroupClaims: v.GroupClaims, CallerOrg: v.CallerOrg, CodeOrg: v.CodeOrg, StorageOrg: v.StorageOrg, CodeShared: v.CodeShared, CodeAccessible: v.CodeAccessible, StorageShared: v.StorageShared, StorageDeployer: v.StorageDeployer, StoragePending: v.StoragePending, CreationUnresolved: v.CreationUnresolved, CreationNamespace: v.CreationNamespace, StorageDeploymentNamespace: v.StorageDeploymentNamespace, CodeDeploymentNamespace: v.CodeDeploymentNamespace, StorageRuntimeHasCode: v.StorageRuntimeHasCode, CallerAddress: v.CallerAddress}
}

// Scenario is explicitly hypothetical input to the offline reference evaluator.
// Facts are operator assertions, not credentials, node traces or authority.
type Scenario struct {
	APIVersion string          `json:"apiVersion"`
	Context    ScenarioContext `json:"context"`
	Frames     []ScenarioFrame `json:"frames"`
}
type ScenarioFrame struct {
	CallType       policycore.CallType `json:"callType"`
	StorageAddress common.Address      `json:"storageAddress"`
	CodeAddress    common.Address      `json:"codeAddress"`
	Calldata       string              `json:"calldata"`
	Value          string              `json:"value"`
	Depth          uint64              `json:"depth"`
	Facts          ScenarioFacts       `json:"facts"`
}

func simulate(ctx context.Context, snapshot *policybundle.CatalogSnapshot, file string, stdout, stderr io.Writer) int {
	raw, err := readABI(ctx, file, 1<<20)
	if err != nil {
		return reportError(stderr, "scenario", err, 1)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := strictjson.ReadValue(decoder, 0, 24)
	if err != nil {
		return reportError(stderr, "scenario", errors.New("invalid or duplicate scenario fields"), 1)
	}
	if _, err = decoder.Token(); err != io.EOF {
		return reportError(stderr, "scenario", errors.New("scenario has trailing data"), 1)
	}
	var scenario Scenario
	if err = strictjson.ExactDecode(value, &scenario); err != nil {
		return reportError(stderr, "scenario", errors.New("unsupported scenario shape"), 1)
	}
	if scenario.APIVersion != "ops.policy-scenario/v1" || len(scenario.Frames) < 1 || len(scenario.Frames) > 256 || len(scenario.Context.Groups) > 256 || len(scenario.Context.LinkedAddresses) > 1024 || len(scenario.Context.GroupSourceClaims) > 256 {
		return reportError(stderr, "scenario", errors.New("scenario version or bounded input limits invalid"), 1)
	}
	evaluated, ok := snapshot.Execution(scenario.Context.Org)
	if !ok {
		return reportError(stderr, "scenario", errors.New("scenario organization has no selected execution policy"), 1)
	}
	frames := make([]policycore.Frame, len(scenario.Frames))
	inputBytes := 0
	for i, f := range scenario.Frames {
		if err := ctx.Err(); err != nil {
			return reportError(stderr, "scenario", err, 1)
		}
		if !strings.HasPrefix(f.Calldata, "0x") || len(f.Calldata)%2 != 0 {
			return reportError(stderr, "scenario", fmt.Errorf("frame %d: calldata must be hex bytes", i), 1)
		}
		data, err := hex.DecodeString(f.Calldata[2:])
		inputBytes += len(data)
		number, valid := new(big.Int).SetString(f.Value, 10)
		if err != nil || !valid || number.Sign() < 0 || number.BitLen() > 256 || number.String() != f.Value || inputBytes > 256<<10 || len(f.Facts.GroupClaims) > 256 {
			return reportError(stderr, "scenario", fmt.Errorf("frame %d: invalid bounded calldata, value or facts", i), 1)
		}
		frame := f.Facts.native()
		frame.CallType = f.CallType
		frame.StorageAddress = f.StorageAddress
		frame.CodeAddress = f.CodeAddress
		frame.Calldata = data
		frame.Value = number
		frame.Depth = f.Depth
		frames[i] = frame
	}
	decision := evaluated.Evaluate(scenario.Context.native(), frames)
	if err := ctx.Err(); err != nil {
		return reportError(stderr, "scenario", err, 1)
	}
	result := struct {
		Action             string              `json:"action"`
		Approved           bool                `json:"approved"`
		Hypothetical       bool                `json:"hypothetical"`
		DeploymentVerified bool                `json:"deploymentVerified"`
		ManifestDigest     policybundle.Digest `json:"manifestDigest"`
		ScenarioDigest     policybundle.Digest `json:"scenarioDigest"`
		Profile            string              `json:"profile"`
		EvaluatorVersion   string              `json:"evaluatorVersion"`
		Decision           policycore.Decision `json:"decision"`
	}{Action: "simulate", Hypothetical: true, ManifestDigest: snapshot.Metadata().ManifestDigest, ScenarioDigest: policybundle.RawDigest(raw), Profile: snapshot.Metadata().Profile, EvaluatorVersion: snapshot.Metadata().EvaluatorVersion, Decision: decision}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return reportError(stderr, "output", err, 1)
	}
	return 0
}
