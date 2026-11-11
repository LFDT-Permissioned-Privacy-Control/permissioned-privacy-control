package ssosql

import "testing"

func TestAppMetadataConcreteBinding(t *testing.T) {
	var nilStore *Store
	for _, s := range []*Store{nilStore, {}, {mode: "app"}} {
		if _, e := s.AppMetadata(); e == nil {
			t.Fatal("unopened app binding accepted")
		}
	}
	f := setup(t)
	app := f.app(t)
	retention := f.ret(t)
	actual, e := app.AppMetadata()
	if e != nil || actual != app.Metadata() {
		t.Fatal("actual app metadata rejected", e)
	}
	if _, e = retention.AppMetadata(); e == nil {
		t.Fatal("retention pointer accepted as app")
	}
	app.Close()
	if _, e = app.AppMetadata(); e == nil {
		t.Fatal("closed app accepted")
	}
}
