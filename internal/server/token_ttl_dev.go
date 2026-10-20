//go:build mockauth

package server

import "time"

func init() {
	AccessTokenTTL = 30 * time.Minute
}
