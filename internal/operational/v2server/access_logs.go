package v2server

import (
	"privacy-proxy/internal/accesslog"
	"privacy-proxy/internal/operational/activitysource"
	"time"
)

func (s *Server) mountAccessLogs(p *dataPlane) error {
	keys, e := dataKeys(s.config.Protected.AdminCursorKeys)
	if e != nil {
		return e
	}
	ring := accesslog.Keys{Active: accesslog.Key{ID: keys.Active.ID, Bytes: keys.Active.Bytes}}
	if keys.Previous != nil {
		ring.Previous = &accesslog.Key{ID: keys.Previous.ID, Bytes: keys.Previous.Bytes}
	}
	service, e := accesslog.New(accesslog.Config{Snapshot: s.core, Reader: activitysource.AdminReader{Store: p.activityReader}, Expected: p.activityReader.Metadata(), Clock: time.Now, Keys: ring})
	if e != nil {
		return e
	}
	handler, e := accesslog.NewHandler(service, p.recorder)
	if e != nil {
		return e
	}
	handler.Register(s.handler)
	return nil
}
