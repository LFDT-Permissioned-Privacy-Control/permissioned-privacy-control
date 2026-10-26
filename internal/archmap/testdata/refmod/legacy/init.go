package legacy

import "errors"

var errStopped = errors.New("stopped")

var started = start()

var lazy = func() int { return start() }

func start() int { return 1 }

var through = start

var _ = through()

func init() { _ = errStopped; _ = lazy }
