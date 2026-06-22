# AgentWarden default admission policy (Rego)
#
# This is the target policy for Phase 3 once the OPA SDK is wired in (see
# docs/ARCHITECTURE.md for why v0.1 ships a native Go evaluator instead).
# It encodes the exact same rules as internal/policy/evaluator.go so the
# two stay in lockstep — when you port this in, internal/policy.Evaluate
# becomes a thin call into `rego.New(...).Eval(ctx)` against this module,
# and the NativeEvaluator can be deleted.
#
# Input shape (matches pkg/types.InterceptRequest plus accumulated state):
#   input.payload            string
#   input.static_violations  []{rule, severity}
#   input.sandbox            {executed, exit_code, timed_out}
#   input.policies           warden.yaml policies block, as parsed JSON

package agentwarden.admission

import rego.v1

default allow := false

# Allow only when no deny rule below fires.
allow if {
	count(deny) == 0
}

deny contains msg if {
	count([v | v := input.static_violations[_]; v.severity == "critical"]) > 0
	input.policies.infrastructure.prevent_destructive_changes == true
	msg := "critical static finding escalated under prevent_destructive_changes"
}

deny contains msg if {
	input.sandbox.executed == true
	input.sandbox.timed_out == true
	msg := "sandbox execution exceeded timeout"
}

deny contains msg if {
	input.sandbox.executed == true
	input.sandbox.exit_code != 0
	msg := sprintf("sandboxed execution exited with status %d", [input.sandbox.exit_code])
}

deny contains msg if {
	some region in regex.find_n(`region\s*[:=]\s*["']?([a-z]{2}-[a-z]+-\d)["']?`, input.payload, -1)
	not region in input.policies.infrastructure.allowed_aws_regions
	msg := sprintf("AWS region %q is not in the allowed list", [region])
}
