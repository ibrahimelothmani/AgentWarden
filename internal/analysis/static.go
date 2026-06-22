// Package analysis implements AgentWarden's Phase 1 static analysis:
// deterministic, pattern-based scanning of an agent's proposed payload for
// dangerous system calls, credential leakage, and forbidden dependencies.
//
// This is intentionally rule-based rather than ML-based: the project's
// design principle (see README) is to avoid using stochastic models to
// police other models. A future iteration can layer real AST parsing
// (tree-sitter) on top of this package without changing its public API —
// Analyzer.Scan already takes the full source and returns structured
// Violations, so swapping the detection strategy underneath is a
// non-breaking change.
package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// rule pairs a compiled pattern with the metadata reported in a Violation.
type rule struct {
	name     string
	pattern  *regexp.Regexp
	severity string
	message  string
}

// Analyzer scans payloads against a fixed set of dangerous-pattern rules
// plus the caller-supplied forbidden package list from warden.yaml.
type Analyzer struct {
	rules             []rule
	forbiddenPackages []string
}

// New builds an Analyzer from the security section of a loaded Config.
func New(sec config.SecurityPolicy) *Analyzer {
	return &Analyzer{
		rules:             builtinRules(),
		forbiddenPackages: sec.ForbiddenPackages,
	}
}

// builtinRules is the default set of dangerous-pattern detectors. Patterns
// are deliberately broad (favoring false positives over false negatives —
// this is a guardrail, and a human can override a flagged-but-safe change
// via the dashboard).
func builtinRules() []rule {
	return []rule{
		{
			name:     "CRITICAL_SYSTEM_COMMAND_DETECTED",
			pattern:  regexp.MustCompile(`(?i)\bos\.system\s*\(|\bsubprocess\.(run|call|Popen)\s*\(|\bexec\.Command\s*\(|\bos/exec\b`),
			severity: "critical",
			message:  "Payload invokes a system shell or external process directly.",
		},
		{
			name:     "CRITICAL_DESTRUCTIVE_FS_OPERATION",
			pattern:  regexp.MustCompile(`rm\s+-rf\s+/|shutil\.rmtree\s*\(|os\.removedirs?\s*\(|DROP\s+TABLE|DROP\s+DATABASE`),
			severity: "critical",
			message:  "Payload contains a recursive or irreversible deletion command.",
		},
		{
			name:     "HIGH_DYNAMIC_CODE_EVALUATION",
			pattern:  regexp.MustCompile(`\beval\s*\(|\bexec\s*\(|new Function\s*\(`),
			severity: "high",
			message:  "Payload dynamically evaluates code at runtime.",
		},
		{
			name:     "HIGH_HARDCODED_CREDENTIAL",
			pattern:  regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"][A-Za-z0-9/+_\-]{12,}['"]`),
			severity: "high",
			message:  "Payload appears to contain a hardcoded credential or secret.",
		},
		{
			name:     "MEDIUM_NETWORK_EGRESS",
			pattern:  regexp.MustCompile(`(?i)requests\.(get|post|put)\s*\(|urllib\.request|http\.client|net/http\.(Get|Post)`),
			severity: "medium",
			message:  "Payload performs outbound network requests.",
		},
		{
			name:     "CRITICAL_DESTRUCTIVE_INFRA_CHANGE",
			pattern:  regexp.MustCompile(`(?i)terraform\s+destroy|aws\s+.*delete-|kubectl\s+delete\s+(namespace|deployment)\s+--all`),
			severity: "critical",
			message:  "Payload issues a broad, destructive infrastructure command.",
		},
	}
}

// importPattern extracts likely-imported package names across a few common
// ecosystems so we can cross-reference them against the forbidden list.
var importPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z0-9_./\-]+)`),               // python "import x", go "import x"
	regexp.MustCompile(`(?m)^\s*from\s+([A-Za-z0-9_.\-]+)\s+import`),        // python "from x import y"
	regexp.MustCompile(`require\(['"]([A-Za-z0-9_@/.\-]+)['"]\)`),           // node require()
	regexp.MustCompile(`from\s+['"]([A-Za-z0-9_@/.\-]+)['"]`),               // ES module import
}

// Scan runs all detection rules against the request payload and returns
// every violation found (it does not short-circuit on the first hit, so
// the caller gets a complete picture in one pass).
func (a *Analyzer) Scan(req types.InterceptRequest) []types.Violation {
	var violations []types.Violation

	for _, r := range a.rules {
		if r.pattern.MatchString(req.Payload) {
			violations = append(violations, types.Violation{
				Phase:    "static_analysis",
				Rule:     r.name,
				Severity: r.severity,
				Message:  r.message,
			})
		}
	}

	for _, pkg := range a.detectImports(req.Payload) {
		if forbidden, matched := a.isForbidden(pkg); forbidden {
			violations = append(violations, types.Violation{
				Phase:    "static_analysis",
				Rule:     "CRITICAL_FORBIDDEN_PACKAGE",
				Severity: "critical",
				Message:  fmt.Sprintf("Payload imports forbidden package %q (matched policy entry %q).", pkg, matched),
			})
		}
	}

	return violations
}

func (a *Analyzer) detectImports(payload string) []string {
	seen := map[string]struct{}{}
	var found []string
	for _, p := range importPatterns {
		for _, m := range p.FindAllStringSubmatch(payload, -1) {
			if len(m) < 2 {
				continue
			}
			name := strings.TrimSpace(m[1])
			if name == "" {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				found = append(found, name)
			}
		}
	}
	return found
}

func (a *Analyzer) isForbidden(pkg string) (bool, string) {
	for _, f := range a.forbiddenPackages {
		if pkg == f || strings.HasPrefix(pkg, f+"/") || strings.Contains(pkg, f) {
			return true, f
		}
	}
	return false, ""
}
