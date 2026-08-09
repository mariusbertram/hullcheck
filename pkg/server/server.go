package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mariusbertram/hullcheck/pkg/config"
	"github.com/mariusbertram/hullcheck/pkg/harbor"
	"github.com/mariusbertram/hullcheck/pkg/jobs"
	"github.com/mariusbertram/hullcheck/pkg/validate"
)

type Server struct {
	cfgManager *config.Manager
	jobsMgr    *jobs.Manager
	harborH    *harbor.Handler
	staticFS   fs.FS
	mux        *http.ServeMux
	readyFn    func() bool
}

// NewServer wires up the HTTP API. readyFn reports whether the server can
// actually run scans yet (e.g. the vulnerability database has finished
// loading) - it gates /readyz so Kubernetes doesn't route traffic before
// then; /healthz stays unconditional so the process isn't restarted while
// that load is still in progress. Pass nil to always report ready.
func NewServer(cfgMgr *config.Manager, jobsMgr *jobs.Manager, staticEmbed embed.FS, readyFn func() bool) *Server {
	hHandler := harbor.NewHandler(jobsMgr)

	subFS, err := fs.Sub(staticEmbed, "public")
	if err != nil {
		subFS = staticEmbed
	}

	s := &Server{
		cfgManager: cfgMgr,
		jobsMgr:    jobsMgr,
		harborH:    hHandler,
		staticFS:   subFS,
		mux:        http.NewServeMux(),
		readyFn:    readyFn,
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	// Health check endpoints
	s.mux.HandleFunc("/healthz", s.handleOK)
	s.mux.HandleFunc("/readyz", s.handleReady)

	// Config API
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handlePutConfig)

	// Scans WebUI API
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/artifacts/{name}", s.handleGetArtifact)
	s.mux.HandleFunc("GET /api/scans/{id}/stream", s.handleStreamScan)

	// Harbor Pluggable Scanner Adapter API v1
	s.mux.HandleFunc("GET /api/v1/metadata", s.harborH.GetMetadata)
	s.mux.HandleFunc("POST /api/v1/scan", s.harborH.AcceptScan)
	s.mux.HandleFunc("GET /api/v1/scan/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		s.harborH.GetReport(w, r, id)
	})

	// Static assets and single-page app fallback
	fileServer := http.FileServer(http.FS(s.staticFS))
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(s.staticFS, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Fallback to index.html for SPA routes
		indexData, err := fs.ReadFile(s.staticFS, "index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexData)
	})
}

// statusRecorder captures the status code written by downstream handlers so
// it can be logged after the request completes (net/http's ResponseWriter
// doesn't expose it directly).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

// Flush lets statusRecorder still satisfy http.Flusher by delegating to the
// wrapped ResponseWriter - embedding only promotes the http.ResponseWriter
// interface's own methods, not Flush, so without this SSE streaming
// (/api/scans/{id}/stream) would break with "Streaming unsupported".
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(rec, r)
	// SSE streams (/stream) can stay open for a long time; skip the noisy
	// per-request line for those and rely on the jobs package's own logs.
	if !strings.HasSuffix(r.URL.Path, "/stream") {
		log.Printf("http: %s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	}
}

func (s *Server) handleOK(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.readyFn != nil && !s.readyFn() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "loading vulnerability database"})
		return
	}
	s.handleOK(w, r)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.cfgManager.GetPublic())
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.cfgManager.Save(cfg); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.cfgManager.GetPublic())
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.jobsMgr.ListJobs())
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image                 string               `json:"image"`
		InsecureSkipTLSVerify bool                 `json:"insecureSkipTlsVerify"`
		InsecureUseHTTP       bool                 `json:"insecureUseHttp"`
		RegistryAuth          *config.RegistryAuth `json:"registryAuth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	image := strings.TrimSpace(body.Image)
	if !validate.IsValidImageRef(image) {
		http.Error(w, `{"error":"A valid image / OCI artifact reference is required, e.g. registry.example.com/namespace/image:tag"}`, http.StatusBadRequest)
		return
	}

	var regAuth map[string]string
	if body.RegistryAuth != nil && body.RegistryAuth.Authority != "" {
		regAuth = map[string]string{
			"authority": body.RegistryAuth.Authority,
			"username":  body.RegistryAuth.Username,
			"password":  body.RegistryAuth.Password,
			"token":     body.RegistryAuth.Token,
		}
	}

	job := s.jobsMgr.CreateJob(image, regAuth, body.InsecureSkipTLSVerify, body.InsecureUseHTTP)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job := s.jobsMgr.GetJob(id)
	if job == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := r.PathValue("name")

	allowed := map[string]bool{"sbom.json": true, "grype.json": true, "grant.json": true}
	if !allowed[name] {
		http.Error(w, `{"error":"unknown artifact"}`, http.StatusBadRequest)
		return
	}

	job := s.jobsMgr.GetJob(id)
	if job == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	file := s.jobsMgr.ArtifactPath(id, name)
	if _, err := os.Stat(file); err != nil {
		http.Error(w, `{"error":"artifact not available"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, file)
}

func (s *Server) handleStreamScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job := s.jobsMgr.GetJob(id)
	if job == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func(evt string, data interface{}) {
		b, _ := json.Marshal(data)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt, string(b))
		flusher.Flush()
	}

	send("status", job)
	for _, entry := range job.Logs {
		send("log", entry)
	}

	if job.Status == "completed" || job.Status == "failed" {
		send("done", job)
		return
	}

	ch, unsubscribe := s.jobsMgr.Subscribe(id)
	defer unsubscribe()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			send(evt.Type, evt.Data)
			if evt.Type == "done" {
				return
			}
		}
	}
}
