package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/server"
	"privacy-proxy/internal/version"
)

func main() {
	// Set up structured logging: JSON in production, text in dev
	var logHandler slog.Handler
	if os.Getenv("ENVIRONMENT") == "production" {
		logHandler = slog.NewJSONHandler(os.Stdout, nil)
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, nil)
	}
	slog.SetDefault(slog.New(logHandler))

	// Emit the build identity first thing so every deployment's logs say
	// exactly which binary is running (RD-1023). Values are injected via
	// -ldflags at build time; a plain `go build` logs version=dev.
	slog.Info("build info",
		"version", version.Version,
		"commit", version.Commit,
		"built", version.BuildTime,
	)

	cfg := config.Load()
	cfg.Version = version.Version

	// Validate configuration (fails fast in production if required values missing)
	if err := cfg.Validate(); err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Warn loudly if mock signatures mode is enabled
	if cfg.MockSignatures {
		slog.Warn("MOCK_SIGNATURES=true - signature verification DISABLED - only for demo, never production")
	}

	// RD-1006 option A: warn when the default literal "explorer" client_id
	// shows up on a production allowlist — operators should use opaque
	// per-environment IDs (e.g. "explorer-prod-${random}") so a leaked or
	// recorded ID from one env can't be replayed against another and audit
	// logs aren't ambiguous across environments.
	if cfg.IsProduction() {
		if _, ok := cfg.OAuthFirstPartyClients["explorer"]; ok {
			slog.Warn("OAUTH_FIRST_PARTY_CLIENTS contains the default literal \"explorer\" in production - use an opaque per-environment client_id (RD-1006 option A)")
		}
	}

	// Log if demo auto-auth is enabled
	if cfg.DemoAutoAuthDelay > 0 {
		slog.Warn("demo mode: auth sessions will auto-complete", "delay", cfg.DemoAutoAuthDelay)
	}

	srv, err := server.New(cfg) // Migrations run automatically in db.New()
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP server for graceful shutdown
	httpServer := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Channel to listen for errors from ListenAndServe
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		slog.Info("starting Open Privacy Suite server", "port", port)
		slog.Info("node URL configured", "url", cfg.NodeURL)
		serverErrors <- srv.RunWithServer(httpServer)
	}()

	// Channel to listen for interrupt/terminate signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or server error
	select {
	case err := <-serverErrors:
		slog.Error("server error", "error", err)
		os.Exit(1)

	case sig := <-shutdown:
		slog.Info("received signal, shutting down", "signal", sig)

		// Give outstanding requests 10 seconds to complete
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Stop accepting new requests and wait for existing ones
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("http server shutdown error", "error", err)
			httpServer.Close()
		}

		// Stop background goroutines
		srv.Stop()
		slog.Info("server stopped gracefully")
	}
}
