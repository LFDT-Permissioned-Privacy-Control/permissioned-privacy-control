//go:build !mockauth

package server

import "context"

// ensureMockUserIsAdmin is a no-op in production builds.
func (s *Server) ensureMockUserIsAdmin(ctx context.Context, userID, userDID string) {}
