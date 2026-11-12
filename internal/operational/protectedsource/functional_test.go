package protectedsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

func TestActualRetainedSourcesComposeAllResources(t *testing.T) {
	node := ownedFunctionalNode(t)
	config := actualFunctionalConfig(t, node)
	source, err := New(t.Context(), config)
	if err != nil {
		t.Fatal("actual source assembly", err)
	}
	plan := source.Plan()
	caseID := uuid.NewString()
	namespace := digestParts("functional-case-namespace")
	base := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: plan.Resources, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 10, End: f.Now + 10}, Level: p.Full}
	keys := d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{33}, 32)}}
	var locator, transactionLocator string
	for _, resource := range []p.Resource{p.AddressHistory, p.Transactions, p.ActivityLogs, p.ActivitySummary, p.SanctionsReport, p.ComplianceReport} {
		t.Run(string(resource), func(t *testing.T) {
			view := d.Report
			if resource == p.AddressHistory || resource == p.Transactions || resource == p.ActivityLogs {
				view = d.List
			}
			selectedScope := base
			if resource == p.Transactions {
				selectedScope.Resources = []p.Resource{p.Transactions}
			}
			normalized, err := d.Normalize(d.Query{Version: 1, Resource: resource, View: view}, selectedScope)
			if err != nil {
				t.Fatal(err)
			}
			scope := d.ReadScope{Namespace: namespace, CaseID: caseID, CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: digestParts("functional-rule"), EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: normalized}
			read, err := source.OpenRetained(t.Context(), scope, nil, nil, nil)
			if err != nil {
				t.Fatal("actual open", err)
			}
			defer read.Close()
			facts, err := read.Read(t.Context(), scope, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resource == p.AddressHistory && len(facts.Addresses) != 1 || resource == p.Transactions && len(facts.Transactions) != 1 {
				t.Fatal("eligible actual ROOT not returned", facts)
			}
			if resource == p.SanctionsReport && (facts.Sanctions == nil || facts.Sanctions.Status != "clear" || facts.Sanctions.ScopedAddressCount != 1) {
				t.Fatal("whole qualified sanctions set", facts)
			}
			if resource == p.ComplianceReport && (facts.Compliance == nil || facts.Compliance.KYC != "not_evaluated" || facts.Compliance.Sanctions.ScopedAddressCount != 1) {
				t.Fatal("actual source composition", facts)
			}
			if err = read.CheckCurrent(t.Context()); err != nil {
				t.Fatal("actual final source recheck", err)
			}
			render, err := d.RenderRetained(plan, scope, read.Descriptors(), facts, d.RenderContext{PreparedAt: config.Clock(), Namespace: scope.Namespace, CaseID: caseID, DataOrganizationID: f.Org, RecipientActorID: scope.RecipientActorID, Keys: keys, Query: normalized, EffectiveUntil: scope.EffectiveUntil}, uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(render)
			if err != nil {
				t.Fatal(err)
			}
			if resource == p.AddressHistory {
				var result struct {
					Result struct {
						Items []struct {
							AddressID string `json:"addressId"`
						} `json:"items"`
					} `json:"result"`
				}
				if err = json.Unmarshal(raw, &result); err != nil || len(result.Result.Items) != 1 {
					t.Fatal(err)
				}
				locator = result.Result.Items[0].AddressID
			}
			if resource == p.Transactions {
				var result struct {
					Result struct {
						Items []struct {
							AddressID string `json:"addressId"`
						} `json:"items"`
					} `json:"result"`
				}
				if err = json.Unmarshal(raw, &result); err != nil || len(result.Result.Items) != 1 || result.Result.Items[0].AddressID == "" {
					t.Fatal("Full transaction row lacks its case-bound detail locator", string(raw), err)
				}
				transactionLocator = result.Result.Items[0].AddressID
			}
		})
	}
	t.Run("full transaction detail", func(t *testing.T) {
		hash := node.tx.Hash().Hex()
		txOnly := base
		txOnly.Resources = []p.Resource{p.Transactions}
		normalized, err := d.Normalize(d.Query{Version: 1, Resource: p.Transactions, View: d.Detail, AddressID: &transactionLocator, TransactionHash: &hash}, txOnly)
		if err != nil {
			t.Fatal(err)
		}
		scope := d.ReadScope{Namespace: namespace, CaseID: caseID, CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: digestParts("functional-rule"), EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: normalized}
		read, err := source.OpenRetained(t.Context(), scope, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer read.Close()
		facts, err := read.Read(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(facts.Transactions) != 1 || facts.Transactions[0].Full == nil || facts.Transactions[0].Full.Input != "0x" {
			t.Fatal("actual signed detail", facts)
		}
		if _, err = d.RenderRetained(plan, scope, read.Descriptors(), facts, d.RenderContext{PreparedAt: config.Clock(), Namespace: scope.Namespace, CaseID: caseID, DataOrganizationID: f.Org, RecipientActorID: scope.RecipientActorID, Keys: keys, Query: normalized, EffectiveUntil: scope.EffectiveUntil}, uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("opaque address list", func(t *testing.T) {
		query := d.Query{Version: 1, Resource: p.Transactions, View: d.List, AddressID: &locator}
		if _, err := d.Normalize(query, base); err == nil {
			t.Fatal("legacy query contract widened")
		}
		normalized, err := d.NormalizeRetained(query, base)
		if err != nil {
			t.Fatal(err)
		}
		scope := d.ReadScope{Namespace: namespace, CaseID: caseID, CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: digestParts("functional-rule"), EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: normalized}
		read, err := source.OpenRetained(t.Context(), scope, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer read.Close()
		facts, err := read.Read(t.Context(), scope, nil)
		if err != nil || len(facts.Transactions) != 1 {
			t.Fatal("opaque target list", facts, err)
		}
		if err = read.CheckCurrent(t.Context()); err != nil {
			t.Fatal(err)
		}
		foreign := scope
		foreign.RecipientActorID = f.Actor(f.Subject)
		if _, err = source.OpenRetained(t.Context(), foreign, nil, nil, nil); !errors.Is(err, d.ErrNotFound) {
			t.Fatal("locator crossed recipient", err)
		}
		invalid := "da1.render." + strings.Repeat("A", 22)
		query.AddressID = &invalid
		foreign = scope
		foreign.Query, err = d.NormalizeRetained(query, base)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = source.OpenRetained(t.Context(), foreign, nil, nil, nil); !errors.Is(err, d.ErrNotFound) {
			t.Fatal("unknown locator broadened to all targets", err)
		}
	})
}
