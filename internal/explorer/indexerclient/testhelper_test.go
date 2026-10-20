package indexerclient

import "time"

// timeOf returns a UTC time.Time for the given Unix epoch seconds.
func timeOf(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}
