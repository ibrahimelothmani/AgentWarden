// Package sandbox implements AgentWarden's Phase 2 dynamic execution:
// running a payload inside an isolated, resource-constrained, network-
// isolated Docker container and observing what it actually does at
// runtime.
//
// DockerRunner talks to the Docker Engine API directly over the Unix
// socket using only the standard library's net/http with a custom
// DialContext. This is a deliberate choice over the official Docker SDK:
// it keeps the binary dependency-free and the attack surface small, both
// of which matter for a tool that sits in the security-critical path of a
// CI/CD pipeline. The Docker Engine API is a stable, versioned REST API,
// so this is a supportable long-term integration, not a shortcut.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// Runner executes a payload in isolation and reports what happened.
// Implementations must never let a caller-supplied payload escape the
// sandbox boundary.
type Runner interface {
	Run(ctx context.Context, req types.InterceptRequest) (*types.SandboxResult, error)
}

// NoopRunner is used when sandbox.enabled is false in warden.yaml, or as a
// safe fallback when the Docker daemon is unreachable (fail-closed callers
// should treat SkippedNote as a signal to deny rather than approve).
type NoopRunner struct{}

func (NoopRunner) Run(_ context.Context, _ types.InterceptRequest) (*types.SandboxResult, error) {
	return &types.SandboxResult{
		Executed:    false,
		SkippedNote: "dynamic sandbox execution is disabled (sandbox.enabled=false)",
	}, nil
}

// DockerRunner spawns an ephemeral, network-isolated container for each
// payload via the Docker Engine API.
type DockerRunner struct {
	httpClient *http.Client
	cfg        config.SandboxConfig
}

// NewDockerRunner builds a DockerRunner that talks to the Docker daemon at
// socketPath (typically /var/run/docker.sock).
func NewDockerRunner(socketPath string, cfg config.SandboxConfig) *DockerRunner {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &DockerRunner{
		httpClient: &http.Client{Transport: transport},
		cfg:        cfg,
	}
}

const dockerAPIVersion = "v1.43"

// containerConfig mirrors the subset of the Docker Engine API's container
// create payload that we actually use. Network is deliberately omitted
// from the host config's allowed modes (we always force "none").
type containerConfig struct {
	Image      string         `json:"Image"`
	Cmd        []string       `json:"Cmd"`
	Entrypoint []string       `json:"Entrypoint,omitempty"`
	Tty        bool           `json:"Tty"`
	HostConfig hostConfigJSON `json:"HostConfig"`
}

type hostConfigJSON struct {
	NetworkMode string `json:"NetworkMode"` // forced to "none"
	Memory      int64  `json:"Memory"`      // bytes
	AutoRemove  bool   `json:"AutoRemove"`
	ReadonlyRootfs bool `json:"ReadonlyRootfs"`
}

// Run creates a fresh container with the payload mounted as the command,
// network access fully disabled, and a hard memory ceiling, then waits up
// to cfg.TimeoutSeconds for it to finish.
func (d *DockerRunner) Run(ctx context.Context, req types.InterceptRequest) (*types.SandboxResult, error) {
	start := time.Now()

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(d.cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	cc := containerConfig{
		Image:      d.cfg.Image,
		Entrypoint: []string{"python3", "-c"},
		Cmd:        []string{req.Payload},
		HostConfig: hostConfigJSON{
			NetworkMode:    "none",
			Memory:         d.cfg.MemoryLimitMB * 1024 * 1024,
			AutoRemove:     false, // we remove explicitly after reading logs
			ReadonlyRootfs: true,
		},
	}

	containerID, err := d.createContainer(timeoutCtx, cc)
	if err != nil {
		return nil, fmt.Errorf("creating sandbox container: %w", err)
	}
	defer d.removeContainer(context.Background(), containerID) //nolint:errcheck // best-effort cleanup

	if err := d.startContainer(timeoutCtx, containerID); err != nil {
		return nil, fmt.Errorf("starting sandbox container: %w", err)
	}

	exitCode, waitErr := d.waitContainer(timeoutCtx, containerID)
	timedOut := timeoutCtx.Err() == context.DeadlineExceeded

	stdout, stderr := d.fetchLogs(context.Background(), containerID)

	result := &types.SandboxResult{
		Executed:   true,
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		DurationMS: time.Since(start).Milliseconds(),
		TimedOut:   timedOut,
	}

	if waitErr != nil && !timedOut {
		return result, fmt.Errorf("waiting for sandbox container: %w", waitErr)
	}
	return result, nil
}

func (d *DockerRunner) createContainer(ctx context.Context, cc containerConfig) (string, error) {
	body, err := json.Marshal(cc)
	if err != nil {
		return "", err
	}

	var out struct {
		ID string `json:"Id"`
	}
	if err := d.do(ctx, http.MethodPost, "/containers/create", bytes.NewReader(body), &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (d *DockerRunner) startContainer(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/start", id), nil, nil)
}

func (d *DockerRunner) waitContainer(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int `json:"StatusCode"`
	}
	if err := d.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/wait", id), nil, &out); err != nil {
		return -1, err
	}
	return out.StatusCode, nil
}

func (d *DockerRunner) fetchLogs(ctx context.Context, id string) (stdout, stderr string) {
	path := fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true", id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+dockerPrefix()+path, nil)
	if err != nil {
		return "", ""
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	// Docker multiplexes stdout/stderr with an 8-byte frame header per
	// chunk; for an MVP sandbox we surface the raw stream rather than
	// fully demultiplexing it, and document that here rather than
	// pretending it's split cleanly.
	return string(raw), ""
}

func (d *DockerRunner) removeContainer(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodDelete, fmt.Sprintf("/containers/%s?force=true", id), nil, nil)
}

func dockerPrefix() string {
	return "/" + dockerAPIVersion
}

// do issues a request against the Docker Engine API over the Unix socket
// and decodes a JSON response into out (if non-nil).
func (d *DockerRunner) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	url := "http://docker" + dockerPrefix() + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("docker daemon unreachable (is /var/run/docker.sock mounted?): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker API %s %s: status %d: %s", method, path, resp.StatusCode, string(raw))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return fmt.Errorf("decoding docker API response: %w", err)
		}
	}
	return nil
}

// Ping checks whether the Docker daemon is reachable, used at startup to
// decide whether to fail closed (deny everything) or fall back to
// NoopRunner with a loud warning, per the operator's choice in config.
func (d *DockerRunner) Ping(ctx context.Context) error {
	return d.do(ctx, http.MethodGet, "/_ping", nil, nil)
}
