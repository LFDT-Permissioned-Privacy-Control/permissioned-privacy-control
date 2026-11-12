package v2server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/explorerindex"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/quotefeed"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcstatepolicy"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

// dataPlane owns concrete restricted adapters. It cannot accept a handler,
// principal, arbitrary SQL callback or a replacement permission evaluator.
type dataPlane struct {
	network             networkidentity.Binding
	native              *rpcengine.Engine
	metadata            *rpcengine.MetadataEngine
	state               *rpcengine.StateEngine
	history             *rpcengine.HistoryEngine
	explorer            *rpcengine.ExplorerEngine
	recorder            *activitylog.Recorder
	feed                *quotefeed.Service
	walletReader        *walletsql.Store
	admissionReader     *admissionsql.Store
	namespaceFacts      *admissionsql.Store
	address             *admissionsql.AddressReader
	addressBinding      creationfacts.AddressReadBinding
	shares              *admissionsql.ShareReader
	shareBinding        historyfacts.ShareBinding
	index               *explorerindex.Reader
	indexBinding        explorerquery.Binding
	activityReader      *activitysql.Reader
	transport           *http.Transport
	reference           creationfacts.Source
	referenceCredential rpcexecution.Credential
	admissionState      admission.ExpectedState
	financial           *admission.Service
}

func endpointCredential(c *Credential) (rpcexecution.Credential, string, error) {
	if c == nil {
		return rpcexecution.Credential{}, "", nil
	}
	value, e := secret(c.FromEnv)
	if e != nil {
		return rpcexecution.Credential{}, "", e
	}
	return rpcexecution.Credential{Header: c.Header, Value: value}, c.FromEnv, nil
}

// buildData opens only existing stores. Bootstrap, migrations, source leases,
// observer publication and privileged retention remain offline operations.
func (s *Server) buildData(ctx context.Context, wb walletops.ServiceBinding, ws walletops.ExpectedState) (*dataPlane, error) {
	c := s.config.Data
	p := &dataPlane{network: networkidentity.Binding{Environment: wb.Environment, ChainID: wb.ChainID, GenesisHash: wb.GenesisHash, DeploymentID: wb.DeploymentID}}
	key, e := p.network.Key()
	if e != nil {
		return nil, ErrInvalid
	}
	network := creationfacts.Network{Key: creationfacts.Digest(key), Environment: wb.Environment, ChainID: wb.ChainID, Genesis: common.HexToHash(wb.GenesisHash), Deployment: wb.DeploymentID}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 32
	transport.MaxIdleConnsPerHost = 16
	transport.ResponseHeaderTimeout = 15 * time.Second
	p.transport = transport
	s.close = append(s.close, transport.CloseIdleConnections)
	credential, ref, e := endpointCredential(c.DefaultNode.Credential)
	if e != nil {
		return nil, e
	}
	p.referenceCredential = credential
	p.reference = creationfacts.Source{Network: network, URL: c.DefaultNode.URL, CredentialRef: ref, CredentialHeader: credential.Header, Profile: "reth-prague-included-creations/v1", PragueStart: c.DefaultNode.PragueStart, PragueEnd: c.DefaultNode.PragueEnd}
	if !p.reference.Valid() {
		return nil, ErrInvalid
	}
	coverage, e := admission.ParseDigest(c.Admission.CoverageDigest)
	if e != nil {
		return nil, e
	}
	p.admissionState = admission.ExpectedState{Generation: c.Admission.Generation, Coverage: coverage}
	if !p.admissionState.Valid() {
		return nil, ErrInvalid
	}
	dsn, e := secret(c.Admission.AppDSNEnv)
	if e != nil {
		return nil, e
	}
	writer, e := admissionsql.OpenCreationObserved(ctx, dsn, admission.DefaultCreationLimits())
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, writer.Close)
	dsn, e = secret(c.Admission.ReaderDSNEnv)
	if e != nil {
		return nil, e
	}
	p.admissionReader, e = admissionsql.OpenReader(ctx, dsn)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.admissionReader.Close)
	p.shareBinding = historyfacts.ShareBinding{Network: p.network, State: p.admissionState, SchemaProfile: historyfacts.ShareSchemaProfile}
	p.shares, e = admissionsql.NewShareReader(p.admissionReader, p.shareBinding)
	if e != nil {
		return nil, e
	}
	dsn, e = secret(c.Admission.FactsDSNEnv)
	if e != nil {
		return nil, e
	}
	p.namespaceFacts, e = admissionsql.OpenCreationFacts(ctx, dsn)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.namespaceFacts.Close)
	sourceSet, e := digest(c.Admission.AddressSourceSetDigest)
	if e != nil {
		return nil, e
	}
	reference, e := digest(c.Admission.AddressReferenceDigest)
	if e != nil {
		return nil, e
	}
	p.addressBinding = creationfacts.AddressReadBinding{Network: network, State: creationfacts.State{Generation: p.admissionState.Generation, Coverage: creationfacts.Digest(coverage)}, SourceSet: creationfacts.Digest(sourceSet), Reference: creationfacts.Digest(reference), Profile: creationfacts.CurrentAddressProfile, Limits: creationfacts.DefaultAddressReadLimits()}
	p.address, e = admissionsql.NewAddressReader(p.namespaceFacts, p.addressBinding)
	if e != nil {
		return nil, e
	}
	dsn, e = secret(c.WalletReaderDSNEnv)
	if e != nil {
		return nil, e
	}
	p.walletReader, e = walletsql.OpenReader(ctx, dsn)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.walletReader.Close)
	ns, e := wb.Namespace()
	if e != nil {
		return nil, e
	}
	wallets, e := walletadapter.New(p.walletReader, ns, ws, time.Now)
	if e != nil {
		return nil, e
	}
	runtime, ok := s.core.Runtime()
	if !ok {
		return nil, ErrInvalid
	}
	rawProfile := rpcexecution.LifecycleSignedProfileID
	if runtime.RawSubmissionMode() == policybundle.RawSubmissionGuardV1 {
		rawProfile = rpcexecution.LifecycleGuardProfileID
	}
	callClients := map[string]*rpcexecution.Client{}
	rawNodes := map[string]rpcengine.RawNodeOptions{}
	metadataClients := map[rpcengine.MetadataBindingKey]*rpcexecution.MetadataClient{}
	stateClients := map[rpcengine.StateBindingKey]*rpcexecution.StateClient{}
	historyClients := map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{}
	nodes := map[string]Node{}
	for _, n := range c.Nodes {
		if n.OrganizationID == "" || nodes[n.OrganizationID].OrganizationID != "" {
			return nil, ErrInvalid
		}
		nodes[n.OrganizationID] = n
	}
	if len(nodes) != len(s.core.Organizations()) {
		return nil, ErrInvalid
	}
	methods := map[string]string{}
	for _, m := range s.core.Methods() {
		methods[m.Name] = m.Canonical
	}
	var captureSources []creationfacts.Source
	for _, org := range s.core.Organizations() {
		n, ok := nodes[org.ID]
		if !ok {
			return nil, ErrInvalid
		}
		credentials := map[string]rpcexecution.Credential{}
		for _, binding := range n.Credentials {
			if _, exists := credentials[binding.FromEnv]; exists {
				return nil, ErrInvalid
			}
			cr, ref, e := endpointCredential(&binding)
			if e != nil {
				return nil, e
			}
			credentials[ref] = cr
		}
		callBinding := rpcexecution.NodeBinding{OrganizationID: org.ID, URL: n.URL, ChainID: wb.ChainID, Profile: runtime.NodeEvidenceProfile(), PragueStartInclusive: n.PragueStart, PragueEndExclusive: n.PragueEnd, AllowUnauthenticated: n.AllowUnauthenticated, Credentials: credentials}
		call, e := rpcexecution.NewClient(transport, callBinding, rpcexecution.DefaultLimits())
		if e != nil {
			return nil, e
		}
		callClients[org.ID] = call
		rawBinding := callBinding
		rawBinding.Profile = rawProfile
		rawClient, e := rpcexecution.NewClient(transport, rawBinding, rpcexecution.DefaultLimits())
		if e != nil {
			return nil, e
		}
		rawRefs := map[string]bool{}
		usedRefs := map[string]bool{}
		for _, id := range s.core.GroupIDs(org.ID) {
			g, ok := s.core.Group(org.ID, id)
			if !ok {
				return nil, ErrInvalid
			}
			ref := ""
			if g.RpcCredential != nil {
				ref = g.RpcCredential.FromEnv
				usedRefs[ref] = true
			}
			cr := credentials[ref]
			if ref != "" && cr.Value == "" {
				return nil, ErrInvalid
			}
			readSource := rpcexecution.MetadataSource{Network: p.network, URL: n.URL, CredentialRef: ref, CredentialHeader: cr.Header, AllowUnauthenticated: n.AllowUnauthenticated}
			source := creationfacts.Source{Network: network, Organization: org.ID, URL: n.URL, CredentialRef: ref, CredentialHeader: cr.Header, Profile: "reth-prague-included-creations/v1", PragueStart: n.PragueStart, PragueEnd: n.PragueEnd}
			for _, name := range g.AllowedMethods {
				canonical := methods[name]
				switch {
				case canonical == "eth_sendTransaction":
					rawRefs[ref] = true
				case metadataFamily(canonical):
					k := rpcengine.MetadataBindingKey{OrganizationID: org.ID, CredentialRef: ref}
					if metadataClients[k] == nil {
						v, e := rpcexecution.NewMetadataClient(transport, readSource, cr, rpcexecution.DefaultMetadataLimits())
						if e != nil {
							return nil, e
						}
						metadataClients[k] = v
					}
				case stateFamily(canonical):
					k := rpcengine.StateBindingKey{OrganizationID: org.ID, CredentialRef: ref}
					if stateClients[k] == nil {
						v, e := rpcexecution.NewStateClient(transport, readSource, cr, rpcexecution.DefaultStateLimits())
						if e != nil {
							return nil, e
						}
						stateClients[k] = v
					}
				case historyFamily(canonical):
					k := rpcengine.HistoryBindingKey{OrganizationID: org.ID, CredentialRef: ref}
					if historyClients[k] == nil {
						v, e := rpcexecution.NewHistoryReadClient(transport, source, cr, rpcexecution.DefaultHistoryReadLimits())
						if e != nil {
							return nil, e
						}
						historyClients[k] = v
					}
				}
			}
		}
		if len(usedRefs) != len(credentials) {
			return nil, ErrInvalid
		}
		if len(rawRefs) > 0 {
			raw := rpcengine.RawNodeOptions{Binding: rawBinding, Transport: transport, Limits: rpcexecution.DefaultLimits()}
			if runtime.RawSubmissionMode() == policybundle.RawSubmissionGuardV1 {
				if n.Guard == nil {
					return nil, ErrInvalid
				}
				guard := n.Guard
				seed, e := binarySecret(guard.SeedEnv, 32)
				if e != nil {
					return nil, e
				}
				raw.Seed, raw.KeyID, raw.HashMode, raw.MaxBatch, raw.ApprovalTTL = seed, guard.KeyID, guard.HashMode, guard.MaxBatch, time.Duration(guard.ApprovalTTLSeconds)*time.Second
				raw.Delivery = nodeapproval.DeliveryOptions{Targets: slices.Clone(guard.Targets), Timeout: 5 * time.Second, MaxInFlight: 16, RetainMax: 4096}
			} else if n.Guard != nil {
				return nil, ErrInvalid
			}
			rawNodes[org.ID] = raw
			for ref := range rawRefs {
				selected, e := rawClient.WithCredential(ref)
				if e != nil {
					return nil, e
				}
				source, e := selected.CaptureSource(network)
				if e != nil {
					return nil, e
				}
				captureSources = append(captureSources, source)
			}
		} else if n.Guard != nil {
			return nil, ErrInvalid
		}
	}
	gate, e := creationcapture.New(creationcapture.Options{Network: network, State: p.addressBinding.State, Reference: p.reference, Sources: captureSources, CaughtUpAssertion: creationfacts.CaughtUpAssertion, Store: writer})
	if e != nil {
		return nil, e
	}
	cursor, e := binarySecret(c.Admission.CursorKeyEnv, 32)
	if e != nil {
		return nil, e
	}
	var quotes admission.QuoteProvider
	if definition, plan, ok := runtime.PriceFeed(); ok {
		var credential quotefeed.CredentialBinding
		if binding := definition.Source().Credential; binding != nil {
			value, e := secret(binding.FromEnv)
			if e != nil {
				return nil, e
			}
			credential = quotefeed.CredentialBinding{FromEnv: binding.FromEnv, Header: c.PriceFeedCredentialHeader, Value: value}
		} else if c.PriceFeedCredentialHeader != "" {
			return nil, ErrInvalid
		}
		p.feed, e = quotefeed.New(quotefeed.Config{Source: definition, Plan: plan, Clock: time.Now, CredentialBinding: credential, AllowPrivate: c.PriceFeedAllowPrivate})
		if e != nil {
			return nil, e
		}
		s.close = append(s.close, p.feed.Close)
		quotes = p.feed
	} else if c.PriceFeedCredentialHeader != "" || c.PriceFeedAllowPrivate {
		return nil, ErrInvalid
	}
	financial, e := admission.NewCreationObserved(admission.Config{Snapshot: s.core, Clock: time.Now, NetworkBinding: admission.NetworkBinding(p.network), ExpectedState: p.admissionState, Store: writer, QuoteProvider: quotes, ExpectedEvidenceProfile: rawProfile, CursorKeyring: admission.CursorKeyring{Active: admission.CursorKey{ID: c.Admission.CursorKeyID, Key: cursor}}, CaptureGate: gate})
	if e != nil {
		return nil, e
	}
	p.financial = financial
	p.native, e = rpcengine.NewCreationObservedWithMinedTrace(s.core, rpcengine.RawOptions{Utilities: &rpcengine.ExecutionUtilityOptions{NodeSigning: c.NodeSigning}, CallClients: callClients, RawNodes: rawNodes, Wallets: wallets, WalletBinding: wb, WalletState: ws, Admission: financial, CaptureGate: gate, Clock: time.Now, Associations: p.address, AssociationBinding: p.addressBinding}, rpcengine.MinedTraceOptions{Shares: p.shares, ShareExpected: p.shareBinding})
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.native.Close)
	raw, e := readPinned(c.MetadataPolicy, 64<<10)
	if e != nil {
		return nil, e
	}
	mp, e := rpcmetadatapolicy.Compile(raw, rpcmetadatapolicy.Digest(sha256.Sum256(raw)))
	if e != nil {
		return nil, e
	}
	raw, e = readPinned(c.StatePolicy, 64<<10)
	if e != nil {
		return nil, e
	}
	sp, e := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
	if e != nil {
		return nil, e
	}
	raw, e = readPinned(c.HistoryPolicy, 64<<10)
	if e != nil {
		return nil, e
	}
	hp, e := rpchistorypolicy.Compile(raw, rpchistorypolicy.Digest(sha256.Sum256(raw)))
	if e != nil {
		return nil, e
	}
	defaultSource := rpcexecution.MetadataSource{Network: p.network, URL: c.DefaultNode.URL, CredentialRef: p.reference.CredentialRef, CredentialHeader: credential.Header, AllowUnauthenticated: ref == ""}
	md, e := rpcexecution.NewMetadataClient(transport, defaultSource, credential, rpcexecution.DefaultMetadataLimits())
	if e != nil {
		return nil, e
	}
	sd, e := rpcexecution.NewStateClient(transport, defaultSource, credential, rpcexecution.DefaultStateLimits())
	if e != nil {
		return nil, e
	}
	hd, e := rpcexecution.NewHistoryReadClient(transport, p.reference, credential, rpcexecution.DefaultHistoryReadLimits())
	if e != nil {
		return nil, e
	}
	p.metadata, e = rpcengine.NewMetadata(rpcengine.MetadataConfig{Snapshot: s.core, Policy: mp, Network: p.network, Default: md, Clients: metadataClients, QueryLimits: rpcexecution.DefaultMetadataLimits(), Clock: time.Now})
	if e != nil {
		return nil, e
	}
	p.state, e = rpcengine.NewState(rpcengine.StateConfig{Snapshot: s.core, Policy: sp, Network: p.network, Default: sd, Clients: stateClients, Associations: p.address, AssociationBinding: p.addressBinding, Wallets: wallets, WalletBinding: wb, WalletState: ws, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: time.Now})
	if e != nil {
		return nil, e
	}
	p.history, e = rpcengine.NewHistory(rpcengine.HistoryConfig{Snapshot: s.core, Policy: hp, Network: p.network, Default: hd, Clients: historyClients, Wallets: wallets, WalletBinding: wb, WalletState: ws, Shares: p.shares, ShareExpected: p.shareBinding, QueryLimits: rpcexecution.DefaultHistoryReadLimits(), Clock: time.Now})
	if e != nil {
		return nil, e
	}
	dsn, e = secret(c.Index.ReaderDSNEnv)
	if e != nil {
		return nil, e
	}
	indexRef, e := digest(c.Index.SourceReferenceDigest)
	if e != nil {
		return nil, e
	}
	p.indexBinding = explorerquery.Binding{Network: p.network, SourceReference: indexRef, SchemaDigest: explorerindex.SchemaDigest(), ConfiguredEpoch: c.Index.ConfiguredEpoch}
	p.index, e = explorerindex.OpenReader(ctx, dsn, p.indexBinding, explorerindex.DefaultLimits())
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.index.Close)
	cursorKey, e := binarySecret(c.Index.CursorKeyEnv, 32)
	if e != nil {
		return nil, e
	}
	pseudonymKey, e := binarySecret(c.Index.PseudonymKeyEnv, 32)
	if e != nil {
		return nil, e
	}
	p.explorer, e = rpcengine.NewExplorer(rpcengine.ExplorerConfig{Snapshot: s.core, History: p.history, State: p.state, Metadata: p.metadata, Index: p.index, IndexExpected: p.indexBinding, CursorKey: cursorKey, PseudonymKey: pseudonymKey})
	if e != nil {
		return nil, e
	}

	scope := activitysql.Scope{NetworkKey: key, SourceID: c.Activity.SourceID, ExpectedGeneration: c.Activity.Generation}
	dsn, e = secret(c.Activity.WriterDSNEnv)
	if e != nil {
		return nil, e
	}
	activityWriter, e := activitysql.OpenWriter(ctx, dsn, scope)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, activityWriter.Close)
	dsn, e = secret(c.Activity.ReaderDSNEnv)
	if e != nil {
		return nil, e
	}
	p.activityReader, e = activitysql.OpenReader(ctx, dsn, scope)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, p.activityReader.Close)
	configDigest, e := digest(c.Activity.ConfigurationDigest)
	if e != nil {
		return nil, e
	}
	labels := []string{"rpc.invalid_request", "rpc.invalid_transport"}
	for _, b := range [][]string{p.metadata.OperationBinding().Methods, p.state.OperationBinding().Methods, p.history.OperationBinding().Methods, p.native.TraceOperationBinding().Methods, p.native.MinedTraceOperationBinding().Methods, p.native.UtilityOperationBinding().Methods, p.explorer.OperationBinding().Methods} {
		labels = append(labels, b...)
	}
	labels = append(labels, "eth_call", "eth_sendRawTransaction")
	slices.Sort(labels)
	labels = slices.Compact(labels)
	p.recorder, e = activitylog.New(ctx, activitylog.Config{Network: p.network, SourceID: c.Activity.SourceID, ProducerID: c.Activity.ProducerID, ExpectedGeneration: c.Activity.Generation, Configuration: activitylog.Digest(configDigest), Methods: labels, Clock: time.Now, BufferDirectory: c.Activity.BufferDirectory, Limits: activitylog.DefaultLimits()}, activityWriter)
	if e != nil {
		return nil, e
	}
	s.close = append(s.close, func() { _ = p.recorder.Close(context.Background()) })
	return p, nil
}

func metadataFamily(s string) bool {
	switch s {
	case "eth_accounts", "eth_blockNumber", "eth_chainId", "eth_feeHistory", "eth_gasPrice", "eth_maxPriorityFeePerGas", "eth_syncing", "net_listening", "net_peerCount", "net_version", "web3_clientVersion", "web3_sha3":
		return true
	}
	return false
}
func stateFamily(s string) bool {
	switch s {
	case "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getProof", "eth_getTransactionCount":
		return true
	}
	return false
}
func historyFamily(s string) bool { _, ok := rpcexecution.HistoryMethodNamed(s); return ok }
