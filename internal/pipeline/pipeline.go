// Package pipeline orchestrates AgentWarden's three verification phases
// against a single incoming request and produces the final admission
// verdict, persisting an audit record for every request regardless of
// outcome.
package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/agentwarden/agentwarden/internal/analysis"
	"github.com/agentwarden/agentwarden/internal/policy"
	"github.com/agentwarden/agentwarden/internal/sandbox"
	"github.com/agentwarden/agentwarden/internal/store"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// Pipeline ties together Phase 1 (static analysis), Phase 2 (sandbox), and
// Phase 3 (policy admission).
type Pipeline struct {
	analyzer  *analysis.Analyzer
	runner    sandbox.Runner
	evaluator policy.Evaluator
	incidents store.Store
}

// New builds a Pipeline from its three phase implementations and an
// incident store for audit logging.
func New(analyzer *analysis.Analyzer, runner sandbox.Runner, evaluator policy.Evaluator, incidents store.Store) *Pipeline {
	return &Pipeline{
		analyzer:  analyzer,
		runner:    runner,
		evaluator: evaluator,
		incidents: incidents,
	}
}

// Run executes all three phases for req and returns the final response.
// A best-effort audit record is written to the incident store regardless
// of the outcome — including when Phase 2 itself errors, since a sandbox
// failure is itself a signal worth keeping.
func (p *Pipeline) Run(ctx context.Context, req types.InterceptRequest) types.InterceptResponse {
	incidentID := newIncidentID()

	// Phase 1: static analysis.
	staticViolations := p.analyzer.Scan(req)

	// Phase 2: dynamic sandbox execution. A sandbox error does not abort
	// the pipeline — it's surfaced to policy admission as a signal, since
	// "we couldn't safely observe this payload" is itself grounds for
	// caution, not silent approval.
	sandboxResult, sandboxErr := p.runner.Run(ctx, req)
	if sandboxErr != nil && sandboxResult == nil {
		sandboxResult = &types.SandboxResult{Executed: false, SkippedNote: sandboxErr.Error()}
	}

	// Phase 3: policy admission, folding in everything learned so far.
	decision := p.evaluator.Evaluate(req, staticViolations, sandboxResult)

	resp := types.InterceptResponse{
		IncidentID: incidentID,
		Violations: decision.Violations,
	}

	if sandboxResult != nil {
		resp.SandboxLogs = sandboxResult.Stdout
	}

	verdict := types.VerdictApproved
	if !decision.Allow {
		verdict = types.VerdictRejected
		resp.Status = types.VerdictRejected
		resp.ActionTaken = "PR creation blocked. Incident logged."
		if len(decision.Violations) > 0 {
			resp.PolicyViolation = decision.Violations[0].Rule
		}
	} else {
		resp.Status = types.VerdictApproved
		resp.ActionTaken = "PR creation allowed to proceed."
	}

	// Persist the audit record. A storage failure must not block the
	// admission decision itself from being returned to the caller, but it
	// is worth surfacing via the action_taken field for visibility.
	if err := p.incidents.Save(types.Incident{
		ID:         incidentID,
		AgentID:    req.AgentID,
		TargetRepo: req.TargetRepo,
		Payload:    req.Payload,
		Verdict:    verdict,
		Violations: decision.Violations,
		Sandbox:    sandboxResult,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		resp.ActionTaken += " (warning: incident audit log write failed)"
	}

	return resp
}

func newIncidentID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is exceptionally unlikely on any real
		// platform; fall back to a timestamp-derived ID rather than
		// panicking in a security-critical request path.
		return "inc_" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return "inc_" + hex.EncodeToString(b)
}
