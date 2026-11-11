package explorerprivacy

import (
	"encoding/json"
	"errors"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"
	"strconv"
	"strings"
)

var errContext = errors.New("incomplete privacy row context")

func RedactTransactions(input TransactionInput, ropts RedactOpts) ([]Transaction, error) {
	if len(input.Rows) == 0 {
		return input.Rows, nil
	}
	if !input.Profile.Strict() && len(input.CalldataParticipants) != len(input.Rows) {
		return nil, errContext
	}
	r := renderer{input.Profile, input.PseudonymKey}
	txs := input.Rows
	visibilityMapDetailed := input.Detailed
	visibilityMap := explorerdata.VisibilityMapFromDetailed(visibilityMapDetailed)
	viewerAddrs := input.ViewerAddresses
	logParticipantTxs := input.LogParticipants
	visibleHashes := ropts.VisibleTxHashes
	viewerIsAdmin := ropts.ViewerIsAdmin
	adminAuditView := ropts.AdminAuditView()
	strict := input.Profile.Strict()
	if strict {
		visibleHashes = nil
		viewerIsAdmin = false
		adminAuditView = false
		ropts.ListedTxHashes = nil
	}
	// 3. Apply redactions
	var redactedTxs []Transaction
	for rowIndex, tx := range txs {
		// Determine whether the viewer is a participant in this transaction.
		// Four orthogonal signals; any one is sufficient.
		//   1. tx-level from / to (the basic case).
		//   2. Legacy hardcoded ERC-20/721/1155 calldata recipient
		//      (isViewerInCalldata) — kept as cheap fast-path for
		//      contracts without a registered ABI.
		//   3. (RD-939 Stage B) ABI-decoded calldata: when the called
		//      contract has a resolvable ABI, decode and check every
		//      address-typed input arg. Catches custom selectors
		//      (the original RD-939 mint(address,…) reproducer).
		//   4. (RD-939 Stage A) Event-log topic appearance: viewer in
		//      any indexed address slot of an accepted event signature.
		//      Authoritative — the EVM emitted it.
		viewerIsFrom := tx.From != "" && viewerAddrs[strings.ToLower(tx.From)]
		viewerIsTo := tx.HasRecipient() && viewerAddrs[strings.ToLower(*tx.To)]
		var viewerIsParticipant bool
		if strict {
			// Strict: the shared tx-level decision, from/to only.
			viewerIsParticipant = readprivacy.DecideTxEnvelope(r.readProfile, readprivacy.TxEnvelopeFacts{
				Surface:       readprivacy.TxSurfaceTransaction,
				IsParticipant: viewerIsFrom || viewerIsTo,
			})
		} else {
			viewerIsCalldataLegacy := isViewerInCalldata(tx.InputData, viewerAddrs)
			viewerIsCalldataABI := input.CalldataParticipants[rowIndex]
			viewerIsLogParticipant := logParticipantTxs[strings.ToLower(tx.Hash)]
			viewerIsParticipant = viewerIsFrom || viewerIsTo ||
				viewerIsCalldataLegacy || viewerIsCalldataABI || viewerIsLogParticipant
		}

		// Resolve base visibility from the shared map.
		baseFromLevel := VisibilityFull
		if tx.From != "" {
			baseFromLevel = visibilityMap[strings.ToLower(tx.From)]
		}
		baseToLevel := VisibilityFull
		if tx.HasRecipient() {
			baseToLevel = visibilityMap[strings.ToLower(*tx.To)]
		}

		// visibleTo override: if this tx was shared with the viewer via the
		// visibleTo param, upgrade both addresses to full visibility — the
		// sender explicitly chose to share this transaction with the viewer.
		// RD-1316: only a genuine tx_visible_to listing (ListedTxHashes)
		// reveals. A hash that is in VisibleTxHashes without a listing came
		// from the RD-1009 transfer-participant union: it keeps the row
		// (txKeptByUnion) but every address renders at the viewer's own level.
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(tx.Hash)]
		txKeptByUnion := visibleHashes[strings.ToLower(tx.Hash)] && !txVisibleToViewer

		// Strict participants receive the full transaction envelope. Standard
		// participant views retain their base visibility policy for pseudonymous
		// addresses and the sender's nonce.
		fromLevel := baseFromLevel
		toLevel := baseToLevel
		if viewerIsParticipant || txVisibleToViewer {
			if (strict && viewerIsParticipant) || fromLevel == VisibilityHidden || fromLevel == VisibilityRedacted {
				fromLevel = VisibilityFull
			}
			if (strict && viewerIsParticipant) || toLevel == VisibilityHidden || toLevel == VisibilityRedacted {
				toLevel = VisibilityFull
			}
		}

		// Strict read profile: only a participant admits the row.
		if strict && !viewerIsParticipant {
			continue
		}

		// If BOTH participants are non-identifiable to the viewer (hidden or
		// redacted after participant override), the row is dropped under strict
		// privacy — showing "[PRIVATE] → [PRIVATE]" leaks transaction existence
		// and timing. The elevated org-admin audit view (gated by the
		// ORG_ADMIN_VIEW_USER_TXS deployment flag) keeps it instead: the admin
		// needs to audit user activity, and the row stays address-private (both
		// sides remain [PRIVATE]); only value/timing are revealed below. Each
		// such reveal is counted so the handler can audit-log the access.
		//
		// Union override (RD-1316): a row kept by the transfer-participant
		// union survives with both sides [PRIVATE]. Under the audit view its
		// value is revealed below, so that reveal is counted too.
		bothHidden := IsNonIdentifiable(fromLevel) && IsNonIdentifiable(toLevel)
		if bothHidden {
			if !adminAuditView && !txKeptByUnion {
				continue
			}
			if adminAuditView {
				ropts.RecordAdminReveal()
			}
		}

		// Contract creation transactions: if the deployer is non-identifiable,
		// the row is dropped under strict privacy ("[PRIVATE] → Contract" leaks
		// deployment activity, timing, and the resulting contract address). The
		// elevated admin audit view keeps it (same gating + audit as above).
		// Skip the re-count when bothHidden already counted this row.
		//
		deployHidden := tx.IsContractCreation() && IsNonIdentifiable(fromLevel)
		if deployHidden && !bothHidden {
			if !adminAuditView && !txKeptByUnion {
				continue
			}
			if adminAuditView {
				ropts.RecordAdminReveal()
			}
		}

		// G10 fix: Non-participant, non-visibleTo txs where one side is hidden
		// are dropped. This aligns explorer visibility with the RPC layer.
		// Exceptions:
		// - Admins see all contract activity (they need to audit the network)
		// - Both sides Full = both identifiable, no information leak
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdmin && !txKeptByUnion {
			if IsNonIdentifiable(fromLevel) || IsNonIdentifiable(toLevel) {
				continue
			}
		}

		redactedTx := tx
		redactedTx.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && IsNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && IsNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visibilityMapDetailed[aLower]; ok {
				redactedTx.AddressMetadata[aLower] = meta.Reason
			}
		}

		// RD-1143: redact the deployed-contract address on a CREATE receipt. It
		// is a first-class address field and must follow the same field-level
		// redaction as from/to — keyed on the CONTRACT's own resolved visibility
		// (it is registered to the deployer's org via the deploy auto-grant, so it
		// resolves to Redacted/Hidden for outsiders and Full for the deployer /
		// org members). The participant/visibleTo override reveals it to the
		// deployer (who is the `from` participant of their own CREATE). The
		// elevated admin audit view deliberately does NOT reveal it: per
		// /docs/security/privacy-requirements the flag reveals existence + value
		// (row survival) but never counterparty/contract addresses. Fail-closed:
		// only the two identifiable levels reveal; Hidden/Redacted AND any
		// unknown level render [PRIVATE]. Runs before the branch split so it
		// applies on every surviving row regardless of from/to outcome.
		if tx.ContractAddress != nil && *tx.ContractAddress != "" {
			caBase := visibilityMap[strings.ToLower(*tx.ContractAddress)]
			caLevel := caBase
			if (strict && viewerIsParticipant) || ((viewerIsParticipant || txVisibleToViewer) && IsNonIdentifiable(caLevel)) {
				caLevel = VisibilityFull
			}
			if caLevel == VisibilityFull || caLevel == VisibilityPseudonymous {
				red := r.applyRedaction(*tx.ContractAddress, caLevel)
				redactedTx.ContractAddress = &red
				setMeta(*tx.ContractAddress, caBase)
			} else {
				p := "[PRIVATE]"
				redactedTx.ContractAddress = &p
			}
		}

		// If one side is non-identifiable (hidden or redacted) but the other is
		// identifiable, replace the non-identifiable side with [PRIVATE] and strip
		// financial data (value, input, error).
		if IsNonIdentifiable(fromLevel) || IsNonIdentifiable(toLevel) {
			if IsNonIdentifiable(fromLevel) {
				redactedTx.From = "[PRIVATE]"
				// Zero out nonce: it reveals the transaction count of a private account,
				// and sequential nonces across [PRIVATE] transactions could link them to the same account.
				redactedTx.Nonce = nil
			} else {
				redactedTx.From = r.applyRedaction(tx.From, fromLevel)
				setMeta(tx.From, baseFromLevel)
			}
			if IsNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redactedTx.To = &p
			} else if tx.HasRecipient() {
				redacted := r.applyRedaction(*tx.To, toLevel)
				redactedTx.To = &redacted
				setMeta(*tx.To, baseToLevel)
			}
			// Under the elevated admin audit view, preserve value so the row is
			// informative and consistent with the Transfer event the admin can
			// already read (RD-751). InputData stays stripped (calldata embeds
			// addresses) and nonce stays nil (it links a private account's txs) —
			// the view reveals volume/timing, never identity.
			//
			if !adminAuditView {
				redactedTx.Value = JSONString("")
			}
			redactedTx.InputData = ""
			redactedTx.Error = nil
			redactedTx.RevertReason = nil
			redactedTxs = append(redactedTxs, redactedTx)
			continue
		}

		// Neither side is hidden or redacted — apply normal redaction
		if tx.From != "" {
			redactedTx.From = r.applyRedaction(tx.From, fromLevel)
			setMeta(tx.From, baseFromLevel)
		}
		if tx.HasRecipient() {
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
			setMeta(*tx.To, baseToLevel)
		}

		// Standard participant views keep the sender's nonce policy based on
		// base visibility. Strict participants receive the same transaction
		// fields as the admitted JSON-RPC envelope.
		if !strict && viewerIsParticipant && (baseFromLevel == VisibilityHidden || baseFromLevel == VisibilityRedacted) {
			redactedTx.Nonce = nil
		}

		redactedTxs = append(redactedTxs, redactedTx)
	}

	// RD-1299 strict transaction rows omit token-transfer counts and categories.
	// The transfers view lists events admitted for the current viewer.
	if r.readProfile.Strict() {
		for i := range redactedTxs {
			redactedTxs[i].TokenTransferCount = 0
			cats := RemoveCategory(redactedTxs[i].TxCategories, "token_transfer")
			if len(cats) == 0 && len(redactedTxs[i].TxCategories) > 0 && redactedTxs[i].HasRecipient() {
				cats = []string{"contract_call"}
			}
			redactedTxs[i].TxCategories = cats
		}
		return redactedTxs, nil
	}

	return redactedTxs, nil
}

func RedactTransfers(input TransferInput, ropts RedactOpts) TransferOutput {
	r := renderer{input.Profile, input.PseudonymKey}
	transfers := input.Rows
	visMapDetailed := input.Detailed
	visMap := explorerdata.VisibilityMapFromDetailed(visMapDetailed)
	viewerAddrs := input.ViewerAddresses
	viewerIsAdminT := ropts.ViewerIsAdmin
	adminAuditView := ropts.AdminAuditView()
	strict := input.Profile.Strict()
	strictAdmitted := input.StrictAdmitted
	if strict {
		viewerIsAdminT = false
		adminAuditView = false
		ropts.ListedTxHashes = nil
	}
	var result []TokenTransfer
	// exempt[i] marks result[i] as admitted by the strict event decision, which
	// already covers event access; it is not re-filtered by GetBatchEventAccess.
	var exempt []bool
	for _, t := range transfers {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != "" && viewerAddrs[strings.ToLower(t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo
		strictRow := false
		if strict {
			strictRow = strictAdmitted[TransferLogKey(t.TxHash, t.LogIndex)]
			// No counterparty reveal under strict: the row renders like the
			// masked log it derives from.
			viewerIsParticipant = false
		}
		// Only genuine tx_visible_to listings reveal transfer fields. The
		// transfer-participant union controls parent-row survival and does not
		// admit sibling transfer rows.
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(t.TxHash)]

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := visMap[strings.ToLower(t.To)]
		// The EVM zero address is a protocol constant used for ERC-20 mints and
		// burns, never an identity that privacy policy can protect. Treat it as
		// public so a visible counterparty does not lose the derived transfer
		// row (or see a misleading [PRIVATE] sender/recipient).
		if IsZeroEVMAddress(t.From) {
			baseFromLevel = VisibilityFull
		}
		if IsZeroEVMAddress(t.To) {
			baseToLevel = VisibilityFull
		}
		fromLevel := baseFromLevel
		toLevel := baseToLevel

		// Participant or visibleTo override
		if viewerIsParticipant || txVisibleToViewer {
			if IsNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if IsNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		if strict {
			if !strictRow {
				continue
			}
			result = append(result, r.renderStrictTransfer(t, baseFromLevel, baseToLevel, visMapDetailed))
			exempt = append(exempt, true)
			continue
		}

		// Drop if both sides are non-identifiable. Under strict privacy this
		// keeps the surrounding transferCount aggregate out of sync with the
		// rows, but that is the conservative default. The elevated org-admin
		// audit view (ORG_ADMIN_VIEW_USER_TXS) keeps the row instead — addresses
		// stay [PRIVATE], only the amount/timing are revealed (below) — and the
		// reveal is counted for audit logging.
		//
		if IsNonIdentifiable(fromLevel) && IsNonIdentifiable(toLevel) {
			if !adminAuditView {
				continue
			}
			ropts.RecordAdminReveal()
		}

		// G10: non-participant, non-visibleTo, non-admin, one side hidden → drop.
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdminT {
			if IsNonIdentifiable(fromLevel) || IsNonIdentifiable(toLevel) {
				continue
			}
		}

		redacted := t
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && IsNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && IsNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip amount
		if IsNonIdentifiable(fromLevel) || IsNonIdentifiable(toLevel) {
			if IsNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if IsNonIdentifiable(toLevel) {
				redacted.To = "[PRIVATE]"
			} else {
				redacted.To = r.applyRedaction(t.To, toLevel)
				setMeta(t.To, baseToLevel)
			}
			// Elevated admin audit view preserves the transfer amount (consistent
			// with the Transfer log the admin can already read); addresses remain
			// [PRIVATE].
			if !adminAuditView {
				redacted.Value = JSONString("")
			}
			if IsZeroEVMAddress(t.From) {
				redacted.From = t.From
			}
			if IsZeroEVMAddress(t.To) {
				redacted.To = t.To
			}
			result = append(result, redacted)
			exempt = append(exempt, false)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		redacted.To = r.applyRedaction(t.To, toLevel)
		setMeta(t.To, baseToLevel)

		result = append(result, redacted)
		exempt = append(exempt, false)
	}

	return TransferOutput{result, exempt}
}

func RedactInternalTransactions(input InternalInput, ropts RedactOpts) ([]InternalTransaction, error) {
	r := renderer{input.Profile, input.PseudonymKey}
	itxs := input.Rows
	visMapDetailed := input.Detailed
	visMap := explorerdata.VisibilityMapFromDetailed(visMapDetailed)
	viewerAddrs := input.ViewerAddresses
	parents := input.Parents
	strict := input.Profile.Strict()
	adminAuditView := ropts.AdminAuditView()
	if strict {
		adminAuditView = false
		ropts.ListedTxHashes = nil
	}
	// RD-1122: parent-tx participants, threaded from the single-hash handler.
	// The viewer is a "parent participant" iff one of their linked EOAs is the
	// parent tx's from or to — computed ONCE (mirrors RedactLogs' isParticipant).
	// This is intentionally restricted to linked-EOA participation: visibleTo
	// viewers are handled by the existing per-frame share paths
	// below, and must NOT trigger the parent-participant reveal (doing so would
	// surface the parent's real counterparty under a pseudonymous lens — the
	// RD-1079 leak class).
	parentParticipantSet := make(map[string]bool, len(ropts.ParentParticipants))
	for _, pa := range ropts.ParentParticipants {
		if pa != "" {
			parentParticipantSet[strings.ToLower(pa)] = true
		}
	}
	viewerIsParentParticipant := false
	for pa := range parentParticipantSet {
		if viewerAddrs[pa] {
			viewerIsParentParticipant = true
			break
		}
	}

	var result []InternalTransaction
	for _, t := range itxs {
		ppSet, ppViewer := parentParticipantSet, viewerIsParentParticipant
		if strict {
			parent := parents[strings.ToLower(t.TxHash)]
			ppSet, ppViewer = map[string]bool{}, false
			if parent != nil {
				if parent.From != "" {
					ppSet[strings.ToLower(parent.From)] = true
				}
				if parent.HasRecipient() {
					ppSet[strings.ToLower(*parent.To)] = true
				}
				ppViewer = readprivacy.DecideTxEnvelope(r.readProfile, readprivacy.TxEnvelopeFacts{
					Surface:       readprivacy.TxSurfaceTransaction,
					IsParticipant: (parent.From != "" && viewerAddrs[strings.ToLower(parent.From)]) || (parent.HasRecipient() && viewerAddrs[strings.ToLower(*parent.To)]),
				})
			}
		}
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != nil && *t.To != "" && viewerAddrs[strings.ToLower(*t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo
		if strict {
			// Frame-level participation counts only within a parent the
			// viewer participated in.
			viewerIsParticipant = viewerIsParticipant && ppViewer
		}

		// RD-1122 per-side parent-participant flags: a frame side qualifies for
		// reveal ONLY when its own address is itself one of the parent's two
		// parties. NEVER blanket-reveal a frame — a frame's `to` is the
		// CALL/STATICCALL/DELEGATECALL target and is attacker-influenceable, so
		// revealing the non-parent side of a `parentParty -> foreignOrgContract`
		// frame would leak a foreign-org private address. Revealing exactly the
		// parent's parties discloses nothing new (they are already shown at the
		// tx/Overview level by the existing top-frame participant override).
		fromIsParentParty := ppViewer && t.From != "" && ppSet[strings.ToLower(t.From)]
		toIsParentParty := ppViewer && t.To != nil && *t.To != "" && ppSet[strings.ToLower(*t.To)]

		// visibleTo override: a frame inherits its parent's genuine share. When
		// the sender listed the viewer on the parent tx (ListedTxHashes), the
		// frame survives and its addresses are revealed, mirroring
		// RedactTransactions/RedactTransfers.
		//
		// RD-1316: the RD-1009 transfer-participant union (VisibleTxHashes)
		// plays no part here, as in RedactTransfers. It keeps the parent row
		// only; the parent's frames follow the ordinary rules below, so a
		// frame with both sides private — another org's call tree, since a
		// frame's target can be any org's private contract (the RD-1122 /
		// RD-1223 concern) — is dropped unless the admin audit view keeps it.
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(t.TxHash)]

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := VisibilityFull
		if t.To != nil && *t.To != "" {
			baseToLevel = visMap[strings.ToLower(*t.To)]
		}
		fromLevel := baseFromLevel
		toLevel := baseToLevel

		// Participant or visibleTo override: reveal counterparty. A genuine
		// share mirrors RedactTransactions/RedactTransfers — the sender chose
		// to show this tx to the viewer, so its frames are revealed too.
		if viewerIsParticipant || txVisibleToViewer {
			if IsNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if IsNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		// RD-1122 per-side parent-participant reveal. Reveal ONLY the side whose
		// address is itself a parent party (see fromIsParentParty/toIsParentParty
		// above). Strictly narrower than the both-sides override above: it never
		// promotes the non-parent side of a frame, so a deep
		// `parentParty -> foreignOrgContract` frame keeps the foreign contract at
		// its standing (Redacted/Hidden) level — no cross-org leak.
		if fromIsParentParty && IsNonIdentifiable(fromLevel) {
			fromLevel = VisibilityFull
		}
		if toIsParentParty && IsNonIdentifiable(toLevel) {
			toLevel = VisibilityFull
		}

		// Drop if both sides are non-identifiable. The elevated org-admin audit
		// view (ORG_ADMIN_VIEW_USER_TXS) keeps the row — addresses stay
		// [PRIVATE], value/timing revealed below — and counts the reveal. This
		// mirrors RedactTransactions/RedactTransfers so internal-tx lists do not
		// contradict the surrounding count for the admin under the flag.
		//
		// txVisibleToViewer above already upgraded fromLevel/toLevel to Full
		// when the parent tx is genuinely shared, so the bothHidden branch
		// cannot fire for those.
		//
		if strict && !ppViewer {
			continue
		}

		bothHidden := IsNonIdentifiable(fromLevel) && IsNonIdentifiable(toLevel)
		if bothHidden {
			if !adminAuditView {
				continue
			}
			ropts.RecordAdminReveal()
		}

		redacted := t
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && IsNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if ppViewer && ppSet[aLower] && IsNonIdentifiable(baseLvl) {
				// RD-1122: revealed because it is a party of the parent tx the
				// viewer participated in (already shown at the tx/Overview level).
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && IsNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip financial data
		if IsNonIdentifiable(fromLevel) || IsNonIdentifiable(toLevel) {
			if IsNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if IsNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redacted.To = &p
			} else if t.To != nil && *t.To != "" {
				r2 := r.applyRedaction(*t.To, toLevel)
				redacted.To = &r2
				setMeta(*t.To, baseToLevel)
			}
			// Elevated admin audit view preserves value; Input/Output stay nil
			// (they can embed addresses / decoded private data).
			// A strict parent participant may see the internal amount even
			// when the unrelated frame counterparty remains private.
			if !adminAuditView && !(strict && ppViewer) {
				redacted.Value = JSONString("")
			}
			redacted.Input = nil
			redacted.Output = nil
			// Strip the trace error: a revert string can embed the hidden
			// counterparty's address or a private reason (e.g. "execution
			// reverted: caller 0xABCD... not authorized"). Top-level
			// RedactTransactions already nils Error on its one-side-hidden
			// branch; this closes the matching gap for internal txs.
			// (REDACTION_SPEC G4 / RD-1177 F2)
			redacted.Error = nil
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		if t.To != nil && *t.To != "" {
			r2 := r.applyRedaction(*t.To, toLevel)
			redacted.To = &r2
			setMeta(*t.To, baseToLevel)
		}

		result = append(result, redacted)
	}
	return result, nil
}

func RedactLogs(input LogInput, opts *RedactOpts) ([]Log, error) {
	r := renderer{input.Profile, input.PseudonymKey}
	logs := input.Rows
	var listedTxHashes map[string]bool
	if opts != nil {
		listedTxHashes = opts.ListedTxHashes
	}
	visMap := input.Visibility
	masterMeta := input.MasterMetadata
	viewerAddrs := input.ViewerAddresses
	isParticipant := input.Participant
	eventRulesMap := input.Rules
	eventRulesResolved := input.RulesResolved
	adminContracts := input.AdminContracts
	unlockableContracts := input.UnlockableContracts
	allowDynamicPayload := input.AllowDynamicPayload
	contractABIs := input.ContractABIs
	// RD-1299: under the strict read profile every log must name one of the
	// viewer's linked addresses in an ABI-indexed address parameter.
	strict := r.readProfile.Strict()
	var selfMatcher *readprivacyabi.IndexedSelfMatcher
	if strict {
		selfMatcher = readprivacyabi.NewIndexedSelfMatcher()
	}

	// Phase 4: apply redactions.
	var result []Log
	for _, l := range logs {
		contractAddrLower := strings.ToLower(l.Address)

		level := visMap[contractAddrLower]
		contractAddr := contractAddrLower

		// Hard floor: a Hidden emitter (unregistered address / EOA, or a
		// foreign-org contract) is dropped unconditionally — before any bypass,
		// including admin. This is defence-in-depth: even if a resolver bug
		// wrongly flags such an emitter as admin/unlockable, a truly
		// inaccessible contract's logs must never surface. (The engine's shared
		// policy handles the grant/rules/participant decision for in-scope
		// emitters below; this floor is the explorer's visibility-level
		// pre-filter, with no RPC equivalent needed — isAdminByContract there
		// can never be set for an unregistered contract.)
		if level == VisibilityHidden {
			continue
		}

		// Resolve the per-log facts and defer the admit/deny verdict to the
		// shared decision engine (readprivacy.DecideLogEmitter, RD-1214/RD-1300) — the
		// SAME function the RPC filter (readprivacy.FilterEventLogs) uses, so the two
		// layers reach identical verdicts and cannot drift. The engine owns the
		// gate order; this block only resolves the facts from the explorer's
		// data model, and the rendering below turns an admit into structured
		// output.
		facts := readprivacy.LogEmitterFacts{
			// RD-890 admin bypass (per-contract, org-scoped).
			IsAdmin: adminContracts[contractAddr],
			// RD-874 visibleTo unlock — the only standalone-grant path. Keyed on
			// the viewer's genuine listing for THIS tx (ListedTxHashes), never on
			// the RD-1009 transfer-participant union in VisibleTxHashes (RD-1307).
			Unlocked: unlockableContracts[contractAddr] && listedTxHashes[strings.ToLower(l.TxHash)],
			// Grant eligibility: a contract grant resolves the emitter to Full
			// for this viewer (GetBatchVisibilityDetailed). No grant → Redacted
			// (registered) or Hidden (unregistered/EOA). Load-bearing (RD-1208).
			HasGrant: level == VisibilityFull,
			// RD-1162 participant/sender (grant-bounded inside the engine).
			IsParticipant: isParticipant,
			// Ordinary visibleTo — additive param-rule fallback only. Like the
			// unlock, keyed on the genuine listing, never the RD-1009 union
			// (RD-1307) — matching the RPC's tx_visible_to check.
			InVisibleTo: listedTxHashes[strings.ToLower(l.TxHash)],
			HasTopic0:   l.Topic0 != nil,
		}

		// Fast drop for emitters with no possible admit path (no admin, no
		// unlock, no grant → Hidden or Redacted/ReasonNoAccess). The engine
		// returns false for all of these; short-circuiting here enforces the
		// grant boundary up front and avoids the (uncached) ABI-resolver DB
		// call for foreign-org logs — the pre-engine early Hidden drop
		// generalised to the full no-grant case (RD-1208/RD-1214).
		if !facts.IsAdmin && !facts.Unlocked && !facts.HasGrant {
			continue
		}

		// RD-889 deny-when-no-ABI + M15 dynamic-payload — the embedded-address
		// protections. Resolved for EVERY candidate log, admin and unlock
		// included, exactly as readprivacy.FilterEventLogs does: the engine admits
		// admin/unlock before reading these facts, but a policy profile that
		// switches the unlock off falls back to the ordinary verdict, which
		// must then see the real ABI/M15 facts rather than permissive defaults.
		// Without a resolvable ABI, non-indexed address params in `data` can't
		// be decoded/redacted.
		resolvedABI := input.ResolvedABIs[contractAddr]
		facts.ABIResolvable = input.ABIResolverAbsent || resolvedABI != ""
		var abiForCheck json.RawMessage
		if raw, ok := contractABIs[contractAddr]; ok && len(raw) > 0 {
			abiForCheck = raw
		} else if resolvedABI != "" {
			abiForCheck = json.RawMessage(resolvedABI)
		}
		if l.Topic0 != nil {
			if len(abiForCheck) > 0 && !allowDynamicPayload[contractAddr] &&
				eventHasDynamicNonIndexedParam(abiForCheck, *l.Topic0) {
				facts.DynamicPayloadDropped = true
			}
		}
		// Strict read profile (RD-1299): the same IndexedSelf predicate the RPC
		// filter applies, on the same ABI. No ABI → never matches.
		if strict {
			facts.IndexedSelf = selfMatcher.Match(string(abiForCheck), collectLogTopics(l), l.Data, viewerAddrs)
		}

		// event_rules resolution (RD-888). When no checker is wired (legacy
		// callers / tests) the gate is disabled — treat as wildcard; the grant
		// gate above still applies. visibleTo extends the param-rule fallback.
		if eventRulesResolved[contractAddr] {
			res := eventRulesMap[contractAddr]
			switch {
			case res.Wildcard:
				facts.Rules = readprivacy.LogEventRulesWildcard
			case len(res.Rules) == 0:
				facts.Rules = readprivacy.LogEventRulesDeny
			default:
				facts.Rules = readprivacy.LogEventRulesAllowlist
				if l.Topic0 != nil {
					topic0Lower := strings.ToLower(*l.Topic0)
					for _, rule := range res.Rules {
						if rule.Topic0 != topic0Lower {
							continue
						}
						facts.Topic0Allowlisted = true
						if len(rule.ParamRules) == 0 {
							facts.EventAllowed = true
							break
						}
						var abiJSON string
						if raw, ok := contractABIs[contractAddr]; ok {
							abiJSON = string(raw)
						}
						if readprivacyabi.MatchesEventParamRules(
							readprivacyabi.EventLogInputs{
								ContractAddress: contractAddr,
								Topics:          collectLogTopics(l),
								Data:            l.Data,
							},
							rule.ParamRules,
							viewerAddrs,
							abiJSON,
						) {
							facts.EventAllowed = true
							break
						}
					}
				}
			}
		} else {
			facts.Rules = readprivacy.LogEventRulesWildcard
		}

		decision := readprivacy.DecideLogEmitter(r.readProfile, facts)
		if !decision.Admit {
			continue
		}

		// Payload policy from the shared decision (RD-1300) — the SAME value the
		// RPC renderer consumes. LogPayloadFull (the RD-874 visibleTo unlock:
		// the contract owner opted in via allow_visibleto_unlock and the sender
		// listed this viewer on this tx) is a full reveal with no field
		// redaction; everything else is masked below.
		if decision.Payload == readprivacy.LogPayloadFull {
			redacted := l
			redacted.AddressMetadata = make(map[string]VisibilityReason)
			result = append(result, redacted)
			continue
		}

		redacted := l
		redacted.AddressMetadata = make(map[string]VisibilityReason)

		setMeta := func(addr string, baseLvl VisibilityLevel) {
			// Emit a metadata reason ONLY for an address that remains
			// IDENTIFIABLE in the rendered log — i.e. VisibilityFull. That is
			// the sole level whose real address survives redaction: topics/data
			// carrying a Redacted, Hidden or Pseudonymous embedded address are
			// zeroed (redactTopicAddress / redactLogData). Writing a reason for
			// such an address keys AddressMetadata by the very address the
			// zeroing hid, handing it back to the viewer in the clear —
			// the RD-1214 metadata-key leak. A zeroed address gets no entry.
			//
			// Note: a participant's counterparty is not revealed here — logs
			// zero all non-Full embedded addresses regardless of participation,
			// so there is no identifiable address to annotate. Per-address
			// counterparty reveal (unified with the RPC field-redaction) is the
			// remaining RD-1214 work; until then the fail-closed posture holds.
			if baseLvl != VisibilityFull {
				return
			}
			aLower := strings.ToLower(addr)
			if reason, ok := masterMeta[aLower]; ok {
				redacted.AddressMetadata[aLower] = reason
			}
		}

		redacted.Address = r.applyRedaction(l.Address, level)
		setMeta(l.Address, visMap[strings.ToLower(l.Address)])

		if level == VisibilityRedacted {
			redacted.Topic0 = nil
			redacted.Topic1 = nil
			redacted.Topic2 = nil
			redacted.Topic3 = nil
			redacted.Data = ""
		} else {
			// Contract is visible — zero every embedded private address in the
			// topics and ABI-decoded data via the SHARED field-redaction
			// primitive (RD-1214). The RPC log filter calls the same
			// RedactLogAddressFields with a visMap resolved from the same
			// GetBatchVisibilityDetailed, so the two layers zero identical
			// addresses by construction.
			topicABI := contractABIs[strings.ToLower(l.Address)]
			redTopics, redData := RedactLogAddressFields(
				[]*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3},
				l.Data, topicABI, l.Topic0, visMap,
			)
			redacted.Topic0, redacted.Topic1, redacted.Topic2, redacted.Topic3 =
				redTopics[0], redTopics[1], redTopics[2], redTopics[3]
			redacted.Data = redData

			// Annotate the embedded addresses that remain visible (setMeta emits
			// a reason only for VisibilityFull addresses — the ones the primitive
			// left intact — so a zeroed address is never keyed into metadata;
			// see the RD-1214 leak fix on setMeta above).
			for _, t := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
				if t == nil {
					continue
				}
				if a, ok := extractTopicAddress(*t); ok {
					setMeta(a, visMap[a])
				}
			}
			if l.Data != "" && l.Topic0 != nil && len(topicABI) > 0 {
				for _, a := range extractDataAddresses(l.Data, topicABI, l.Topic0) {
					setMeta(a, visMap[a])
				}
			}
		}

		result = append(result, redacted)
	}
	return result, nil
}

func RedactTokenHolders(input HolderInput) ([]TokenHolder, error) {
	r := renderer{pseudonymKey: input.PseudonymKey}
	holders := input.Rows
	visMap := input.Visibility
	var result []TokenHolder
	for _, h := range holders {
		level := visMap[strings.ToLower(h.Address)]
		if level == VisibilityHidden {
			continue
		}
		h.Address = r.applyRedaction(h.Address, level)
		if level == VisibilityRedacted {
			// Strip balance and percentage: they reveal financial position even when the address is masked.
			h.Balance = JSONString("")
			h.Percentage = 0
		}
		result = append(result, h)
	}
	return result, nil
}

func RemoveCategory(cats []string, remove string) []string {
	var result []string
	for _, c := range cats {
		if c != remove {
			result = append(result, c)
		}
	}
	return result
}

func TransferLogKey(txHash string, logIndex int) string {
	return strings.ToLower(txHash) + ":" + strconv.Itoa(logIndex)
}

func IsNonIdentifiable(level VisibilityLevel) bool {
	return level == VisibilityHidden || level == VisibilityRedacted
}

func IsZeroEVMAddress(addr string) bool {
	normalized := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return len(normalized) == 40 && strings.Trim(normalized, "0") == ""
}

func (r renderer) renderStrictTransfer(t TokenTransfer, fromLevel, toLevel VisibilityLevel, detailed map[string]AddressVisibility) TokenTransfer {
	out := t
	out.AddressMetadata = make(map[string]VisibilityReason)
	side := func(addr string, lvl VisibilityLevel) string {
		if IsZeroEVMAddress(addr) {
			return addr
		}
		if IsNonIdentifiable(lvl) {
			return "[PRIVATE]"
		}
		if lvl == VisibilityFull {
			if meta, ok := detailed[strings.ToLower(addr)]; ok {
				out.AddressMetadata[strings.ToLower(addr)] = meta.Reason
			}
		}
		return r.applyRedaction(addr, lvl)
	}
	out.From = side(t.From, fromLevel)
	out.To = side(t.To, toLevel)
	return out
}

func (r renderer) applyRedaction(address string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return address
	case VisibilityPseudonymous:
		return explorerdata.GeneratePseudonym(address, r.pseudonymKey)
	case VisibilityRedacted:
		return "[PRIVATE]"
	case VisibilityHidden:
		return "[PRIVATE]"
	default:
		return "[PRIVATE]" // Fail safe
	}
}

type renderer struct {
	readProfile  readprivacy.ReadProfile
	pseudonymKey []byte
}

func ApplyRedaction(address string, level VisibilityLevel, key []byte) string {
	return (renderer{pseudonymKey: key}).applyRedaction(address, level)
}
func RenderStrictTransfer(t TokenTransfer, fromLevel, toLevel VisibilityLevel, detailed map[string]AddressVisibility, key []byte) TokenTransfer {
	return (renderer{pseudonymKey: key}).renderStrictTransfer(t, fromLevel, toLevel, detailed)
}
func isViewerInCalldata(data string, linked map[string]bool) bool {
	return readprivacyabi.IsViewerInCalldata(data, linked)
}
func collectLogTopics(l Log) []string { return readprivacyabi.CollectLogTopics(l) }
func extractTopicAddress(topic string) (string, bool) {
	return readprivacyabi.ExtractTopicAddress(topic)
}
func extractDataAddresses(data string, abi json.RawMessage, topic0 *string) []string {
	return readprivacyabi.ExtractDataAddresses(data, abi, topic0)
}
func eventHasDynamicNonIndexedParam(abi json.RawMessage, topic0 string) bool {
	return readprivacyabi.EventHasDynamicNonIndexedParamJSON(abi, topic0)
}
func RedactLogAddressFields(topics []*string, data string, abi json.RawMessage, topic0 *string, visMap VisibilityMap) ([]*string, string) {
	return readprivacyabi.RedactLogAddressFields(topics, data, abi, topic0, visMap)
}
