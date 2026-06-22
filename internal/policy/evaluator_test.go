package policy

import (
	"testing"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

func defaultPolicies() config.Policies {
	return config.Default().Policies
}

func TestEvaluate_CleanRequestIsAllowed(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies())
	d := e.Evaluate(types.InterceptRequest{Payload: "print('hello world')"}, nil, nil)
	if !d.Allow {
		t.Fatalf("expected Allow=true, got violations: %+v", d.Violations)
	}
}

func TestEvaluate_TooManyDeletionsDenied(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies()) // max_file_deletions: 3
	payload := `
os.remove("a.txt")
os.remove("b.txt")
os.remove("c.txt")
os.remove("d.txt")
`
	d := e.Evaluate(types.InterceptRequest{Payload: payload}, nil, nil)
	if d.Allow {
		t.Fatal("expected Allow=false when deletions exceed policy limit")
	}
	if !hasRule(d.Violations, "POLICY_MAX_FILE_DELETIONS_EXCEEDED") {
		t.Errorf("expected POLICY_MAX_FILE_DELETIONS_EXCEEDED, got %+v", d.Violations)
	}
}

func TestEvaluate_NetworkIngressDeniedByDefault(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies()) // allow_network_ingress: false
	d := e.Evaluate(types.InterceptRequest{Payload: `srv.listen(8080)`}, nil, nil)
	if d.Allow {
		t.Fatal("expected Allow=false for network listener under default policy")
	}
	if !hasRule(d.Violations, "POLICY_NETWORK_INGRESS_DISALLOWED") {
		t.Errorf("expected POLICY_NETWORK_INGRESS_DISALLOWED, got %+v", d.Violations)
	}
}

func TestEvaluate_DisallowedAWSRegionDenied(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies()) // allowed: us-east-1, eu-west-1
	d := e.Evaluate(types.InterceptRequest{Payload: `region: "ap-southeast-1"`}, nil, nil)
	if d.Allow {
		t.Fatal("expected Allow=false for disallowed AWS region")
	}
	if !hasRule(d.Violations, "POLICY_AWS_REGION_NOT_ALLOWED") {
		t.Errorf("expected POLICY_AWS_REGION_NOT_ALLOWED, got %+v", d.Violations)
	}
}

func TestEvaluate_AllowedAWSRegionPasses(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies())
	d := e.Evaluate(types.InterceptRequest{Payload: `region: "us-east-1"`}, nil, nil)
	if !d.Allow {
		t.Fatalf("expected Allow=true for allowed AWS region, got %+v", d.Violations)
	}
}

func TestEvaluate_PriorCriticalFindingEscalatesToDenial(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies()) // prevent_destructive_changes: true
	prior := []types.Violation{{Phase: "static_analysis", Rule: "CRITICAL_SYSTEM_COMMAND_DETECTED", Severity: "critical"}}
	d := e.Evaluate(types.InterceptRequest{Payload: "ok"}, prior, nil)
	if d.Allow {
		t.Fatal("expected Allow=false when a critical static finding is present")
	}
	if !hasRule(d.Violations, "POLICY_DESTRUCTIVE_CHANGE_BLOCKED") {
		t.Errorf("expected POLICY_DESTRUCTIVE_CHANGE_BLOCKED, got %+v", d.Violations)
	}
}

func TestEvaluate_SandboxTimeoutDenied(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies())
	sandbox := &types.SandboxResult{Executed: true, TimedOut: true}
	d := e.Evaluate(types.InterceptRequest{Payload: "ok"}, nil, sandbox)
	if d.Allow {
		t.Fatal("expected Allow=false on sandbox timeout")
	}
	if !hasRule(d.Violations, "POLICY_SANDBOX_TIMEOUT") {
		t.Errorf("expected POLICY_SANDBOX_TIMEOUT, got %+v", d.Violations)
	}
}

func TestEvaluate_SandboxNonZeroExitDenied(t *testing.T) {
	e := NewNativeEvaluator(defaultPolicies())
	sandbox := &types.SandboxResult{Executed: true, ExitCode: 1}
	d := e.Evaluate(types.InterceptRequest{Payload: "ok"}, nil, sandbox)
	if d.Allow {
		t.Fatal("expected Allow=false on non-zero sandbox exit")
	}
}

func hasRule(violations []types.Violation, rule string) bool {
	for _, v := range violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}
