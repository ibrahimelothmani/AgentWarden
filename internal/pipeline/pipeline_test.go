package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/agentwarden/agentwarden/internal/analysis"
	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/internal/policy"
	"github.com/agentwarden/agentwarden/internal/store"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// fakeRunner lets tests control the sandbox outcome without Docker.
type fakeRunner struct {
	result *types.SandboxResult
	err    error
}

func (f fakeRunner) Run(_ context.Context, _ types.InterceptRequest) (*types.SandboxResult, error) {
	return f.result, f.err
}

func newTestPipeline(runner fakeRunner) (*Pipeline, store.Store) {
	cfg := config.Default()
	a := analysis.New(cfg.Policies.Security)
	e := policy.NewNativeEvaluator(cfg.Policies)
	s := store.NewMemoryStore()
	return New(a, runner, e, s), s
}

func TestPipeline_Run_CleanPayloadApproved(t *testing.T) {
	p, s := newTestPipeline(fakeRunner{result: &types.SandboxResult{Executed: true, ExitCode: 0}})

	resp := p.Run(context.Background(), types.InterceptRequest{
		AgentID: "dev-agent-01", TargetRepo: "org/svc", Payload: "print('hello')",
	})

	if resp.Status != types.VerdictApproved {
		t.Fatalf("Status = %q, want APPROVED; violations=%+v", resp.Status, resp.Violations)
	}
	if resp.IncidentID == "" {
		t.Error("expected non-empty IncidentID")
	}

	incidents, _ := s.List(0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(incidents))
	}
	if incidents[0].Verdict != types.VerdictApproved {
		t.Errorf("stored verdict = %q, want APPROVED", incidents[0].Verdict)
	}
}

func TestPipeline_Run_DangerousPayloadRejected(t *testing.T) {
	p, s := newTestPipeline(fakeRunner{result: &types.SandboxResult{Executed: true, ExitCode: 0}})

	resp := p.Run(context.Background(), types.InterceptRequest{
		AgentID: "dev-agent-01", TargetRepo: "org/prod-service",
		Payload: `import os; os.system("rm -rf /")`,
	})

	if resp.Status != types.VerdictRejected {
		t.Fatalf("Status = %q, want REJECTED", resp.Status)
	}
	if resp.PolicyViolation == "" {
		t.Error("expected a non-empty PolicyViolation")
	}
	if resp.ActionTaken == "" {
		t.Error("expected a non-empty ActionTaken")
	}

	incidents, _ := s.List(0)
	if incidents[0].Verdict != types.VerdictRejected {
		t.Errorf("stored verdict = %q, want REJECTED", incidents[0].Verdict)
	}
}

func TestPipeline_Run_SandboxErrorDoesNotCrashPipeline(t *testing.T) {
	p, _ := newTestPipeline(fakeRunner{result: nil, err: errors.New("docker daemon unreachable")})

	resp := p.Run(context.Background(), types.InterceptRequest{Payload: "print(1)"})

	// A sandbox error should still produce a complete, well-formed response.
	if resp.IncidentID == "" {
		t.Error("expected non-empty IncidentID even when sandbox errors")
	}
	if resp.Status == "" {
		t.Error("expected a non-empty Status even when sandbox errors")
	}
}

func TestPipeline_Run_EachRequestGetsUniqueIncidentID(t *testing.T) {
	p, _ := newTestPipeline(fakeRunner{result: &types.SandboxResult{Executed: true}})

	resp1 := p.Run(context.Background(), types.InterceptRequest{Payload: "a"})
	resp2 := p.Run(context.Background(), types.InterceptRequest{Payload: "b"})

	if resp1.IncidentID == resp2.IncidentID {
		t.Error("expected distinct incident IDs across requests")
	}
}
