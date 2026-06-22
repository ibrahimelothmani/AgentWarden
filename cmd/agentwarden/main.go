// Command agentwarden starts the AgentWarden admission controller: an
// HTTP server that intercepts AI-agent-proposed changes, runs them through
// static analysis, dynamic sandbox execution, and policy admission, and
// either allows or blocks the resulting GitOps action.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentwarden/agentwarden/internal/analysis"
	"github.com/agentwarden/agentwarden/internal/api"
	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/internal/pipeline"
	"github.com/agentwarden/agentwarden/internal/policy"
	"github.com/agentwarden/agentwarden/internal/sandbox"
	"github.com/agentwarden/agentwarden/internal/store"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe a locally running instance's /healthz and exit 0/1 (used by Docker HEALTHCHECK; works without a shell)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("agentwarden " + version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	if err := run(logger); err != nil {
		logger.Error("fatal startup error", "error", err)
		os.Exit(1)
	}
}

// runHealthcheck performs a single self-check HTTP request against this
// instance's own /healthz endpoint. Distroless runtime images ship no
// shell and no curl/wget, so Docker's HEALTHCHECK must shell out to the
// application binary itself — this is that entrypoint.
func runHealthcheck() int {
	addr := envOr("WARDEN_ADDR", ":8080")
	url := "http://localhost" + addr + "/healthz"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck failed: status", resp.StatusCode)
		return 1
	}
	return 0
}

func run(logger *slog.Logger) error {
	configPath := envOr("WARDEN_CONFIG", "warden.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger.Info("loaded configuration", "path", configPath, "sandbox_enabled", cfg.Sandbox.Enabled)

	analyzer := analysis.New(cfg.Policies.Security)
	evaluator := policy.NewNativeEvaluator(cfg.Policies)
	incidents := store.NewMemoryStore()

	runner := buildSandboxRunner(cfg, logger)

	p := pipeline.New(analyzer, runner, evaluator, incidents)
	srv := api.NewServer(p, incidents, logger)

	addr := envOr("WARDEN_ADDR", ":8080")
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("agentwarden listening", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// buildSandboxRunner decides between the real Docker-backed runner and the
// NoopRunner fallback. It fails loud (logs a warning) rather than silently
// disabling a security control when the daemon is unreachable, and the
// operator can choose fail-open vs fail-closed behavior via
// WARDEN_SANDBOX_FAIL_CLOSED.
func buildSandboxRunner(cfg *config.Config, logger *slog.Logger) sandbox.Runner {
	if !cfg.Sandbox.Enabled {
		logger.Warn("sandbox execution disabled via config; Phase 2 will be skipped for every request")
		return sandbox.NoopRunner{}
	}

	socketPath := envOr("WARDEN_DOCKER_SOCKET", "/var/run/docker.sock")
	runner := sandbox.NewDockerRunner(socketPath, cfg.Sandbox)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runner.Ping(ctx); err != nil {
		logger.Warn("docker daemon unreachable at startup; falling back to NoopRunner for Phase 2",
			"socket", socketPath, "error", err)
		return sandbox.NoopRunner{}
	}

	logger.Info("docker sandbox runner ready", "socket", socketPath, "image", cfg.Sandbox.Image)
	return runner
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
