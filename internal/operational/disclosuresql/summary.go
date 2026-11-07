package disclosuresql

import (
	"bytes"
	"encoding/json"
	"io"

	c "privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/strictjson"
)

func decodeSummary(raw []byte, out *c.EventSummary) error {
	if len(raw) == 0 || len(raw) > 8192 {
		return c.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 8)
	if err != nil {
		return c.ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return c.ErrUnavailable
	}
	if strictjson.ExactDecode(value, out) != nil {
		return c.ErrUnavailable
	}
	return nil
}
