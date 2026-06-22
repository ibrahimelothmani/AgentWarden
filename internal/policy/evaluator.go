// Package policy implements AgentWarden's Phase 3 policy admission: the
// final gate that evaluates accumulated violations and infrastructure
// intent against the rules declared in warden.yaml.
//
// Design note: the project's stated architecture uses Open Policy Agent
// (Rego) for this phase. This package ships a native Go Evaluator that
// implements the exact same warden.yaml schema and produces the same
// Decision shape that a Rego-backed implementation would. It is wired
// behind the Evaluator interface specifically so the OPA SDK can be
// substituted later (see /policies/default.rego for the target policy
// already written in Rego, and docs/ARCHITECTURE.md for why OPA isn't
// wired in this build).
package policy

import (
	"fmt"
	"regexp"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// Decision is the outcome of policy admission for one request.
type Decision struct {
	Allow      bool
	Violations []types.Violation
}

// Evaluator evaluates a request (plus everything learned about it in
// earlier pipeline phases) against policy and returns an admission
// Decision. Implementations must be safe for concurrent use.
type Evaluator interface {
	Evaluate(req types.InterceptRequest, priorViolations []types.Violation, sandbox *types.SandboxResult) Decision
}

// NativeEvaluator is the built-in, dependency-free Evaluator implementation.
type NativeEvaluator struct {
	policies config.Policies
}

// NewNativeEvaluator builds an Evaluator from the policies block of a
// loaded Config.
func NewNativeEvaluator(p config.Policies) *NativeEvaluator {
	return &NativeEvaluator{policies: p}
}

var (
	awsRegionPattern   = regexp.MustCompile(`(?i)region\s*[:=]\s*["']?([a-z]{2}-[a-z]+-\d)["']?`)
	deletionCountPattern = regexp.MustCompile(`(?i)\b(os\.remove|os\.unlink|delete_file|fs\.unlinkSync)\s*\(`)
)

// Evaluate applies every policy rule and returns ALLOW only if nothing
// fired AND the sandbox phase (when it ran) reported a clean exit.
func (e *NativeEvaluator) Evaluate(req types.InterceptRequest, priorViolations []types.Violation, sandbox *types.SandboxResult) Decision {
	var violations []types.Violation
	violations = append(violations, priorViolations...)

	// Rule: max_file_deletions
	if count := len(deletionCountPattern.FindAllString(req.Payload, -1)); count > e.policies.Security.MaxFileDeletions {
		violations = append(violations, types.Violation{
			Phase:    "policy_admission",
			Rule:     "POLICY_MAX_FILE_DELETIONS_EXCEEDED",
			Severity: "high",
			Message: fmt.Sprintf("Payload performs %d file deletions, exceeding policy limit of %d.",
				count, e.policies.Security.MaxFileDeletions),
		})
	}

	// Rule: allow_network_ingress
	if !e.policies.Security.AllowNetworkIngress && containsNetworkListener(req.Payload) {
		violations = append(violations, types.Violation{
			Phase:    "policy_admission",
			Rule:     "POLICY_NETWORK_INGRESS_DISALLOWED",
			Severity: "high",
			Message:  "Payload opens a network listener but policy disallows inbound network ingress.",
		})
	}

	// Rule: allowed_aws_regions
	if matches := awsRegionPattern.FindAllStringSubmatch(req.Payload, -1); len(matches) > 0 {
		for _, m := range matches {
			region := m[1]
			if !contains(e.policies.Infrastructure.AllowedAWSRegions, region) {
				violations = append(violations, types.Violation{
					Phase:    "policy_admission",
					Rule:     "POLICY_AWS_REGION_NOT_ALLOWED",
					Severity: "high",
					Message:  fmt.Sprintf("Payload targets AWS region %q, which is not in the allowed region list.", region),
				})
			}
		}
	}

	// Rule: prevent_destructive_changes — escalates any prior critical
	// finding from static analysis into an outright admission denial.
	if e.policies.Infrastructure.PreventDestructiveChanges {
		for _, v := range priorViolations {
			if v.Severity == "critical" {
				violations = append(violations, types.Violation{
					Phase:    "policy_admission",
					Rule:     "POLICY_DESTRUCTIVE_CHANGE_BLOCKED",
					Severity: "critical",
					Message:  fmt.Sprintf("Critical finding %q escalated to admission denial under prevent_destructive_changes.", v.Rule),
				})
				break
			}
		}
	}

	// Rule: sandbox outcome — a non-zero exit or timeout during dynamic
	// execution denies admission regardless of static findings.
	if sandbox != nil && sandbox.Executed {
		if sandbox.TimedOut {
			violations = append(violations, types.Violation{
				Phase:    "policy_admission",
				Rule:     "POLICY_SANDBOX_TIMEOUT",
				Severity: "high",
				Message:  "Payload exceeded the sandbox execution timeout.",
			})
		} else if sandbox.ExitCode != 0 {
			violations = append(violations, types.Violation{
				Phase:    "policy_admission",
				Rule:     "POLICY_SANDBOX_NONZERO_EXIT",
				Severity: "medium",
				Message:  fmt.Sprintf("Sandboxed execution exited with non-zero status %d.", sandbox.ExitCode),
			})
		}
	}

	return Decision{
		Allow:      len(violations) == 0,
		Violations: violations,
	}
}

var networkListenerPattern = regexp.MustCompile(`(?i)\.listen\s*\(|net\.Listen\s*\(|socket\.bind\s*\(|app\.run\s*\(.*0\.0\.0\.0`)

func containsNetworkListener(payload string) bool {
	return networkListenerPattern.MatchString(payload)
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
