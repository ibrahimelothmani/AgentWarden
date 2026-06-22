package analysis

import (
	"testing"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

func newTestAnalyzer() *Analyzer {
	return New(config.SecurityPolicy{
		ForbiddenPackages: []string{"unsafe-eval", "crypto-miner"},
	})
}

func containsRule(violations []types.Violation, rule string) bool {
	for _, v := range violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestScan_DetectsSystemCommand(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: `import os; os.system("rm -rf /")`})

	if !containsRule(violations, "CRITICAL_SYSTEM_COMMAND_DETECTED") {
		t.Errorf("expected CRITICAL_SYSTEM_COMMAND_DETECTED, got %+v", violations)
	}
	if !containsRule(violations, "CRITICAL_DESTRUCTIVE_FS_OPERATION") {
		t.Errorf("expected CRITICAL_DESTRUCTIVE_FS_OPERATION, got %+v", violations)
	}
}

func TestScan_DetectsEval(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: `result = eval(user_input)`})
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "HIGH_DYNAMIC_CODE_EVALUATION" {
		t.Errorf("Rule = %q, want HIGH_DYNAMIC_CODE_EVALUATION", violations[0].Rule)
	}
}

func TestScan_DetectsHardcodedSecret(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: `api_key = "FAKE_KEY_FOR_TESTING_ONLY"`})
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "HIGH_HARDCODED_CREDENTIAL" {
		t.Errorf("Rule = %q, want HIGH_HARDCODED_CREDENTIAL", violations[0].Rule)
	}
}

func TestScan_DetectsForbiddenPackageImport(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: "import unsafe-eval\nprint('hi')"})
	if !containsRule(violations, "CRITICAL_FORBIDDEN_PACKAGE") {
		t.Errorf("expected CRITICAL_FORBIDDEN_PACKAGE, got %+v", violations)
	}
}

func TestScan_DetectsDestructiveInfraCommand(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: "terraform destroy -auto-approve"})
	if !containsRule(violations, "CRITICAL_DESTRUCTIVE_INFRA_CHANGE") {
		t.Errorf("expected CRITICAL_DESTRUCTIVE_INFRA_CHANGE, got %+v", violations)
	}
}

func TestScan_CleanPayloadProducesNoViolations(t *testing.T) {
	a := newTestAnalyzer()
	violations := a.Scan(types.InterceptRequest{Payload: "func add(a, b int) int {\n\treturn a + b\n}"})
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %+v", violations)
	}
}

func TestScan_MultipleViolationsAllReported(t *testing.T) {
	a := newTestAnalyzer()
	payload := `
import os
api_key = "AKIAAAAAAAAAAAAAAAAAAAAAA"
os.system("rm -rf /tmp/data")
`
	violations := a.Scan(types.InterceptRequest{Payload: payload})
	if len(violations) < 3 {
		t.Errorf("expected at least 3 violations, got %d: %+v", len(violations), violations)
	}
}
