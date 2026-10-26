package store

// DB is the data handle.
type DB struct{ rows []string }

// Rows returns every row.
func (d *DB) Rows() []string { return d.rows }
