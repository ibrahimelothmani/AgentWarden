// Package types defines the shared data structures passed between
// AgentWarden's pipeline stages (static analysis -> sandbox -> policy
// admission) and exposed over the HTTP API.
package types

import "time"

// Verdict is the final outcome of running a payload through the pipeline.
type Verdict string

const (
	VerdictApproved Verdict = "APPROVED"
	VerdictRejected Verdict = "REJECTED"
	VerdictError    Verdict = "ERROR"
)

// InterceptRequest is the payload submitted by an agent (or the proxy
// sitting in front of one) to POST /v1/intercept.
type InterceptRequest struct {
	AgentID    string `json:"agent_id"`
	TargetRepo string `json:"target_repo"`
	Payload    string `json:"payload"`
	// Language is optional; when empty the static analyzer falls back to
	// heuristic detection based on payload content.
	Language string `json:"language,omitempty"`
}

// Violation describes a single rule break surfaced by any pipeline phase.
type Violation struct {
	Phase    string `json:"phase"`    // "static_analysis" | "sandbox" | "policy_admission"
	Rule     string `json:"rule"`     // machine-readable rule identifier
	Severity string `json:"severity"` // "critical" | "high" | "medium" | "low"
	Message  string `json:"message"`
}

// SandboxResult captures what happened when a payload was executed inside
// the isolated container.
type SandboxResult struct {
	Executed     bool   `json:"executed"`
	ExitCode     int    `json:"exit_code"`
	Stdout       string `json:"stdout,omitempty"`
	Stderr       string `json:"stderr,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
	TimedOut     bool   `json:"timed_out"`
	SkippedNote  string `json:"skipped_note,omitempty"`
}

// InterceptResponse is returned to the caller after the full pipeline runs.
type InterceptResponse struct {
	Status          Verdict         `json:"status"`
	PolicyViolation string          `json:"policy_violation,omitempty"`
	Violations      []Violation     `json:"violations,omitempty"`
	SandboxLogs     string          `json:"sandbox_logs,omitempty"`
	ActionTaken     string          `json:"action_taken"`
	IncidentID      string          `json:"incident_id"`
}

// Incident is the persisted record of one intercepted payload, used to
// drive the dashboard's history view.
type Incident struct {
	ID         string          `json:"id"`
	AgentID    string          `json:"agent_id"`
	TargetRepo string          `json:"target_repo"`
	Payload    string          `json:"payload"`
	Verdict    Verdict         `json:"verdict"`
	Violations []Violation     `json:"violations"`
	Sandbox    *SandboxResult  `json:"sandbox,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}
