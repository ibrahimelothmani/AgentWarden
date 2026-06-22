package sandbox

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

func TestNoopRunner_ReportsNotExecuted(t *testing.T) {
	r := NoopRunner{}
	res, err := r.Run(context.Background(), types.InterceptRequest{Payload: "print(1)"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Executed {
		t.Error("expected Executed=false for NoopRunner")
	}
	if res.SkippedNote == "" {
		t.Error("expected a SkippedNote explaining why execution was skipped")
	}
}

// fakeDockerDaemon spins up a minimal HTTP server over a Unix socket that
// mimics just enough of the Docker Engine API for DockerRunner.Run to
// complete successfully, without requiring an actual Docker daemon.
func fakeDockerDaemon(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "docker.sock")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/create", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Id": "fake-container-id"})
	})
	mux.HandleFunc("/v1.43/containers/fake-container-id/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1.43/containers/fake-container-id/wait", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"StatusCode": exitCode})
	})
	mux.HandleFunc("/v1.43/containers/fake-container-id/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake sandboxed output\n"))
	})
	mux.HandleFunc("/v1.43/containers/fake-container-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		}
	})

	srv := httptest.NewUnstartedServer(mux)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening on fake socket: %v", err)
	}
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)

	return sockPath
}

func TestDockerRunner_Run_SuccessfulExecution(t *testing.T) {
	sockPath := fakeDockerDaemon(t, 0)
	runner := NewDockerRunner(sockPath, config.SandboxConfig{
		Image:          "python:3.12-slim",
		TimeoutSeconds: 5,
		MemoryLimitMB:  128,
	})

	res, err := runner.Run(context.Background(), types.InterceptRequest{Payload: "print('hi')"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Executed {
		t.Error("expected Executed=true")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if res.TimedOut {
		t.Error("expected TimedOut=false")
	}
}

func TestDockerRunner_Run_NonZeroExit(t *testing.T) {
	sockPath := fakeDockerDaemon(t, 1)
	runner := NewDockerRunner(sockPath, config.SandboxConfig{
		Image:          "python:3.12-slim",
		TimeoutSeconds: 5,
		MemoryLimitMB:  128,
	})

	res, err := runner.Run(context.Background(), types.InterceptRequest{Payload: "import sys; sys.exit(1)"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", res.ExitCode)
	}
}

func TestDockerRunner_Ping_UnreachableDaemonErrors(t *testing.T) {
	runner := NewDockerRunner(filepath.Join(t.TempDir(), "nonexistent.sock"), config.SandboxConfig{
		Image: "python:3.12-slim", TimeoutSeconds: 5, MemoryLimitMB: 128,
	})
	if err := runner.Ping(context.Background()); err == nil {
		t.Fatal("expected error pinging nonexistent docker socket, got nil")
	}
}
