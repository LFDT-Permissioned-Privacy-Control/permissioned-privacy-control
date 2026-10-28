package legacy

// Old is the legacy path.
func Old() {}

// Other is another legacy path.
func Other() {}

// Thing is a legacy component.
type Thing struct{}

// Count makes Thing usable as a perimeter sink.
func (*Thing) Count(string) {}

// New builds a Thing.
func New() *Thing { return &Thing{} }
