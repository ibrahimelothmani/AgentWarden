package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentwarden/agentwarden/internal/analysis"
	"github.com/agentwarden/agentwarden/internal/config"
	"github.com/agentwarden/agentwarden/internal/pipeline"
	"github.com/agentwarden/agentwarden/internal/policy"
	"github.com/agentwarden/agentwarden/internal/sandbox"
	"github.com/agentwarden/agentwarden/internal/store"
	"github.com/agentwarden/agentwarden/pkg/types"
)

func newTestServer() *Server {
	cfg := config.Default()
	a := analysis.New(cfg.Policies.Security)
	e := policy.NewNativeEvaluator(cfg.Policies)
	s := store.NewMemoryStore()
	r := sandbox.NoopRunner{}
	p := pipeline.New(a, r, e, s)
	return NewServer(p, s, nil)
}

func doRequest(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf).WithContext(context.Background())
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	srv := newTestServer()
	rec := doRequest(t, srv, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestIntercept_CleanPayloadReturns200(t *testing.T) {
	srv := newTestServer()
	rec := doRequest(t, srv, http.MethodPost, "/v1/intercept", types.InterceptRequest{
		AgentID: "dev-agent-01", TargetRepo: "org/svc", Payload: "print('hi')",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp types.InterceptResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Status != types.VerdictApproved {
		t.Errorf("Status = %q, want APPROVED", resp.Status)
	}
}

func TestIntercept_DangerousPayloadReturns403(t *testing.T) {
	srv := newTestServer()
	rec := doRequest(t, srv, http.MethodPost, "/v1/intercept", types.InterceptRequest{
		AgentID: "dev-agent-01", TargetRepo: "org/prod-service",
		Payload: `import os; os.system("rm -rf /")`,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	var resp types.InterceptResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != types.VerdictRejected {
		t.Errorf("Status = %q, want REJECTED", resp.Status)
	}
	if resp.PolicyViolation == "" {
		t.Error("expected non-empty policy_violation")
	}
}

func TestIntercept_MissingFieldsReturns400(t *testing.T) {
	srv := newTestServer()
	rec := doRequest(t, srv, http.MethodPost, "/v1/intercept", types.InterceptRequest{Payload: "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestIntercept_InvalidJSONReturns400(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/intercept", bytes.NewBufferString("{not json"))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestListIncidents_ReflectsPriorIntercepts(t *testing.T) {
	srv := newTestServer()
	doRequest(t, srv, http.MethodPost, "/v1/intercept", types.InterceptRequest{
		AgentID: "a", TargetRepo: "r", Payload: "print(1)",
	})

	rec := doRequest(t, srv, http.MethodGet, "/v1/incidents", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var incidents []types.Incident
	if err := json.Unmarshal(rec.Body.Bytes(), &incidents); err != nil {
		t.Fatalf("decoding incidents: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("len(incidents) = %d, want 1", len(incidents))
	}
}

func TestGetIncident_NotFoundReturns404(t *testing.T) {
	srv := newTestServer()
	rec := doRequest(t, srv, http.MethodGet, "/v1/incidents/does-not-exist", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
