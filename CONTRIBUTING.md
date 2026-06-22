# Contributing to AgentWarden

Thanks for taking the time to contribute. AgentWarden is an opinionated
project (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the reasoning
behind major choices), but we welcome bug fixes, new detection rules,
alternative policy backends, and performance improvements.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | ≥ 1.22 | Backend |
| Node | ≥ 20 | Web dashboard |
| Docker | any recent | Sandbox execution (optional for dev) |
| make | any | Convenience targets |

---

## Getting started

```bash
git clone https://github.com/ibrahimelothmani/AgentWarden.git
cd agentwarden

# Backend
go mod download
make test          # all green before you touch anything
make run           # starts on :8080

# Dashboard (separate terminal)
make web-install
make web-dev       # starts on :5173, proxies /v1 to :8080
```

---

## Running tests

```bash
make test          # go test ./... -count=1
make cover         # generates coverage.html
```

All packages must stay green and no package may drop below its current
coverage floor. Coverage targets are listed in `docs/ARCHITECTURE.md`.

### Writing tests

- Use stdlib `testing` only — no testify (see Architecture doc for why).
- Use `t.TempDir()` for file fixtures.
- Name tests `TestUnit_Condition_ExpectedBehavior`.
- Tests in `internal/sandbox` may use the `fakeDockerDaemon` helper to
  avoid requiring a real Docker daemon.

---

## Adding a detection rule

Static analysis rules live in `internal/analysis/static.go` in the
`builtinRules()` function. Each rule is a `rule` struct:

```go
{
    name:     "CRITICAL_MY_NEW_RULE",      // ALL_CAPS, prefixed with severity
    pattern:  regexp.MustCompile(`...`),   // deliberately broad — FP > FN
    severity: "critical",                  // critical | high | medium | low
    message:  "Human-readable explanation of what was detected.",
},
```

Add a corresponding test case in `internal/analysis/static_test.go`.

---

## Code style

```bash
go vet ./...          # must be clean
gofmt -w .            # or goimports -w .
golangci-lint run     # optional but recommended
```

CI enforces `go vet` and a clean build. `golangci-lint` is recommended
locally but not blocking on CI yet.

---

## Pull request checklist

- [ ] `make test` passes locally
- [ ] `go vet ./...` is clean
- [ ] New behaviour has test coverage
- [ ] `docs/ARCHITECTURE.md` updated if a design decision changed
- [ ] PR description explains *why*, not just *what*

---

## Commit style

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(analysis): add detection rule for SSRF via DNS rebinding
fix(sandbox): handle empty log stream without panicking
docs(arch): document fail-closed sandbox upgrade path
```

---

## Reporting a security vulnerability

Do **not** open a public issue for security bugs. Email
`security@agentwarden.dev` (or open a GitHub private security advisory)
with a description and reproduction steps. We aim to triage within 48 hours.
