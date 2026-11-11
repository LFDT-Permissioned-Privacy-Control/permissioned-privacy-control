package policybundle_test

import (
	"slices"
	"testing"

	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
)

func TestDeliveryConsumerSharesOneActualCoreAuthority(t *testing.T) {
	fixture := f.DefaultStateFixture(t)
	plain := f.StateSnapshot(t, fixture)
	fixture.HistoryConsumer = true
	history := f.StateSnapshot(t, fixture)
	fixture.DeliveryConsumer = true
	delivery := f.StateSnapshot(t, fixture)
	if plain.DisclosureConsumerEnabled() || history.DisclosureConsumerEnabled() || !delivery.DisclosureConsumerEnabled() || !delivery.HistoryConsumerEnabled() {
		t.Fatal("consumer registration widened old selection")
	}
	if _, ok := delivery.Disclosure(); !ok {
		t.Fatal("approved disclosure rules missing")
	}
	if _, ok := delivery.Compliance(); !ok {
		t.Fatal("approved compliance missing")
	}
	if delivery.Metadata().Profile != policybundle.RuntimeCreationObservedProfileID || !slices.Contains(delivery.Requirements().Capabilities, policybundle.CapabilityRuntimeDisclosure) {
		t.Fatal("delivery capability not approved")
	}
	identityPlain, _ := plain.Identity()
	identityDelivery, _ := delivery.Identity()
	if identityPlain.Digest() != identityDelivery.Digest() {
		t.Fatal("delivery registration replaced identity authority")
	}
	if plain.Metadata().ManifestDigest == delivery.Metadata().ManifestDigest || history.Metadata().ManifestDigest == delivery.Metadata().ManifestDigest {
		t.Fatal("consumer requirement omitted from approved digest")
	}
}
