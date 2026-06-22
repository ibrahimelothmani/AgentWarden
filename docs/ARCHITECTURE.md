# AgentWarden — Architecture

This document explains the key design decisions in AgentWarden's v0.1
implementation and records the tradeoffs that were made deliberately,
so future contributors understand *why* the code is shaped the way it is
rather than just *how*.

---

## System Overview

```
                         ┌─────────────────────────────────────┐
Agent / Git webhook  ──► │  POST /v1/intercept                 │
                         │                                     │
                         │  ┌──────────────────────────────┐   │
                         │  │  Phase 1: Static Analysis    │   │
                         │  │  internal/analysis           │   │
                         │  │  · regex rule engine         │   │
                         │  │  · forbidden package check   │   │
                         │  └─────────────┬────────────────┘   │
                         │                │ violations          │
                         │  ┌─────────────▼────────────────┐   │
                         │  │  Phase 2: Sandbox Execution  │   │
                         │  │  internal/sandbox            │   │
                         │  │  · Docker Engine API (unix)  │   │
                         │  │  · network=none, readonly fs │   │
                         │  │  · memory + timeout caps     │   │
                         │  └─────────────┬────────────────┘   │
                         │                │ SandboxResult       │
                         │  ┌─────────────▼────────────────┐   │
                         │  │  Phase 3: Policy Admission   │   │
                         │  │  internal/policy             │   │
                         │  │  · warden.yaml rule eval     │   │
                         │  │  · sandbox outcome check     │   │
                         │  └─────────────┬────────────────┘   │
                         │                │ Decision            │
                         │  ┌─────────────▼────────────────┐   │
                         │  │  Audit Store                 │   │
                         │  │  internal/store              │   │
                         │  │  · in-memory (v0.1)          │   │
                         │  │  · Postgres-ready interface  │   │
                         │  └──────────────────────────────┘   │
                         │                                     │
                    200  │◄──── APPROVED / 403 REJECTED ───────│
                         └─────────────────────────────────────┘
                                         │
                                GET /v1/incidents
                                         │
                                  ┌──────▼──────┐
                                  │  Dashboard  │
                                  │  web/       │
                                  └─────────────┘
```

---

## Dependency Strategy

AgentWarden uses exactly **three external Go dependencies**:

| Package | Purpose |
|---------|---------|
| `github.com/go-chi/chi/v5` | HTTP routing (lightweight, stdlib-compatible) |
| `github.com/goccy/go-yaml` | YAML parsing for `warden.yaml` |
| *(stdlib)* | Everything else |

This is a deliberate choice. A security-critical admission controller should
be auditable in full. The fewer lines of third-party code run in the request
path, the smaller the supply-chain attack surface. Both chi and goccy/go-yaml
are narrow, well-maintained libraries with minimal transitive dependencies.

---

## Decision: Native Evaluator instead of OPA SDK

### What the README says

The project's stated architecture calls for Open Policy Agent (Rego) as the
Phase 3 admission engine. The `policies/default.rego` file ships the exact
policy logic in real Rego syntax.

### What v0.1 ships

`internal/policy.NativeEvaluator` — a Go implementation of the same rules
that uses `regexp` and config struct comparisons rather than the OPA runtime.

### Why

The OPA Go SDK (`github.com/open-policy-agent/opa`) transitively requires:

- `gopkg.in/yaml.v3` (host `gopkg.in` — blocked in the CI sandbox)
- Multiple `golang.org/x/*` packages (host `golang.org` — blocked)
- A WebAssembly runtime (`bytecodealliance/wasmtime-go`)

At OPA v0.68.0 the full transitive closure is ~60 packages and >30 MB of
compiled binary. For an admission controller that claims "minimal footprint"
this is a hard-to-justify dependency, separate from the compilation issue.

### The contract that makes this swappable

```go
// internal/policy/evaluator.go

type Evaluator interface {
    Evaluate(req types.InterceptRequest,
             priorViolations []types.Violation,
             sandbox *types.SandboxResult) Decision
}
```

Both `NativeEvaluator` and a future `OPAEvaluator` implement this interface.
The pipeline holds an `Evaluator`, not a concrete type, so swapping them is
a one-line change in `cmd/agentwarden/main.go`:

```go
// Today
evaluator := policy.NewNativeEvaluator(cfg.Policies)

// After wiring OPA
evaluator := policy.NewOPAEvaluator("policies/default.rego", cfg.Policies)
```

### How to complete the OPA integration

```bash
# On a machine with full internet access:
go get github.com/open-policy-agent/opa@latest
```

Then implement `OPAEvaluator` in `internal/policy/opa.go`:

```go
func (e *OPAEvaluator) Evaluate(req types.InterceptRequest,
    priorViolations []types.Violation,
    sandbox *types.SandboxResult) Decision {

    r := rego.New(
        rego.Query("data.agentwarden.admission.allow"),
        rego.Load([]string{e.policyPath}, nil),
        rego.Input(buildInput(req, priorViolations, sandbox, e.policies)),
    )
    rs, err := r.Eval(context.Background())
    // ... map to Decision
}
```

---

## Decision: Stdlib-only Docker Client

### What the official client offers

`github.com/docker/docker/client` provides a full, typed Go SDK for the
Docker Engine API. It's the canonical choice.

### Why we don't use it

`github.com/docker/go-connections@v0.7.0` (a transitive dependency) requires
`go >= 1.23`. The project targets `go 1.22` (Ubuntu LTS default, still the
most widely deployed Go version in CI pipelines). Bumping to Go 1.23 just to
pull in the Docker SDK is a larger footprint change than warranted.

### What we do instead

`internal/sandbox.DockerRunner` implements the five Docker API calls it needs
(`POST /containers/create`, `POST /containers/{id}/start`,
`POST /containers/{id}/wait`, `GET /containers/{id}/logs`,
`DELETE /containers/{id}`) directly over the Unix socket via a custom
`http.Transport.DialContext`. The Docker Engine API is a stable, versioned
HTTP API (we pin to `v1.43`), so this is a supportable long-term approach —
not a hack.

### Known MVP limitation: log demultiplexing

Docker's `/containers/{id}/logs` endpoint returns a multiplexed stream with
an 8-byte frame header per chunk. `DockerRunner.fetchLogs` returns the raw
stream bytes rather than fully demultiplexed stdout/stderr. This is
documented in a code comment. A follow-up can implement the 8-byte header
parsing from the [Docker API docs](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerAttach).

---

## Decision: Fail-open vs Fail-closed for Sandbox

When the Docker daemon is unreachable at startup (e.g., running locally
without Docker, or in a CI job that doesn't mount the socket),
`buildSandboxRunner` logs a warning and falls back to `NoopRunner`. The
server still starts and processes requests — Phase 1 and Phase 3 still run.

This is **fail-open** for the sandbox phase specifically, not for the
admission decision overall. A payload that passes static analysis and policy
will be approved even without sandbox data.

**To make it fail-closed**: check for `NoopRunner` in the pipeline, and
treat `SandboxResult.SkippedNote != ""` as a denial reason. A future
`WARDEN_SANDBOX_FAIL_CLOSED=true` environment variable is the intended
upgrade path.

---

## Incident Store

`internal/store.MemoryStore` is an in-process, sorted map behind a
`sync.RWMutex`. It satisfies the `Store` interface for v0.1 without
dependencies. The interface is:

```go
type Store interface {
    Save(types.Incident) error
    List(limit int) ([]types.Incident, error)
    Get(id string) (types.Incident, bool, error)
}
```

A Postgres-backed implementation would look like:

```go
type PostgresStore struct{ db *sql.DB }

func (s *PostgresStore) Save(inc types.Incident) error {
    _, err := s.db.Exec(`INSERT INTO incidents ... ON CONFLICT (id) DO UPDATE ...`, ...)
    return err
}
```

There is no schema migration tool wired in v0.1; `golang-migrate/migrate` is
the recommended addition when this path is taken.

---

## Test Strategy

| Package | Coverage | Approach |
|---------|----------|----------|
| `internal/config` | 85% | stdlib `testing`, temp-dir YAML fixtures |
| `internal/analysis` | 93% | stdlib `testing`, inline payloads |
| `internal/policy` | 100% | stdlib `testing`, table-driven |
| `internal/sandbox` | 81% | stdlib `testing` + fake Docker daemon over real Unix socket |
| `internal/pipeline` | 92% | `fakeRunner` stub, full pipeline smoke |
| `internal/api` | 87% | `httptest.NewRecorder`, full HTTP cycle |
| `internal/store` | 100% | stdlib `testing` |

**No external test framework** is used. The project intentionally avoids
`testify` because `testify/assert` transitively requires `gopkg.in/yaml.v3`,
conflicting with the dependency minimalism principle above. stdlib `testing`
with descriptive `t.Fatalf` messages is equally readable and faster to
compile.

---

## Directory Layout

```
agentwarden/
├── cmd/agentwarden/    # Binary entrypoint — wires deps together, HTTP lifecycle
├── internal/
│   ├── analysis/       # Phase 1: static pattern scanning
│   ├── api/            # HTTP router, handlers, request/response mapping
│   ├── config/         # warden.yaml loading and validation
│   ├── pipeline/       # Orchestration of all three phases
│   ├── policy/         # Phase 3: admission decision engine
│   ├── sandbox/        # Phase 2: Docker runtime execution
│   └── store/          # Incident persistence
├── pkg/types/          # Shared domain types (no internal imports)
├── policies/           # Rego files (for future OPA integration)
├── web/                # React + Vite + Tailwind dashboard
├── docs/               # Architecture documentation (this file)
├── .github/workflows/  # CI/CD (GitHub Actions)
├── Dockerfile          # Multi-stage build → distroless runtime
├── docker-compose.yml  # Local stack (with Docker socket mount)
├── Makefile            # Developer workflow shortcuts
└── warden.yaml         # Default policy configuration
```
