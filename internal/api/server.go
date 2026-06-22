// Package api exposes AgentWarden's pipeline over HTTP: the /v1/intercept
// endpoint that agents (or a Git webhook proxy in front of them) call with
// proposed changes, plus read endpoints the dashboard uses to render
// incident history.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/agentwarden/agentwarden/internal/pipeline"
	"github.com/agentwarden/agentwarden/internal/store"
	"github.com/agentwarden/agentwarden/pkg/types"
)

// Server holds the dependencies needed to handle HTTP requests.
type Server struct {
	pipeline  *pipeline.Pipeline
	incidents store.Store
	logger    *slog.Logger
}

// NewServer builds a Server and its chi router.
func NewServer(p *pipeline.Pipeline, incidents store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{pipeline: p, incidents: incidents, logger: logger}
}

// Router builds the full HTTP route tree.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealthz)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/intercept", s.handleIntercept)
		r.Get("/incidents", s.handleListIncidents)
		r.Get("/incidents/{id}", s.handleGetIncident)
	})

	return r
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	var req types.InterceptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}

	if req.AgentID == "" || req.TargetRepo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id and target_repo are required"})
		return
	}
	if req.Payload == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload must not be empty"})
		return
	}

	resp := s.pipeline.Run(r.Context(), req)

	status := http.StatusOK
	if resp.Status == types.VerdictRejected {
		status = http.StatusForbidden
	}
	writeJSON(w, status, resp)
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := s.incidents.List(100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list incidents"})
		return
	}
	writeJSON(w, http.StatusOK, incidents)
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	incident, ok, err := s.incidents.Get(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load incident"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
