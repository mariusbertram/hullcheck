package main

import (
	"context"
	"embed"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mariusbertram/hullcheck/pkg/config"
	"github.com/mariusbertram/hullcheck/pkg/jobs"
	"github.com/mariusbertram/hullcheck/pkg/scanner"
	"github.com/mariusbertram/hullcheck/pkg/server"
)

// drainDelay gives kube-proxy/the ingress time to remove this pod from
// Endpoints (readyz starts failing as soon as we catch the signal) before we
// stop accepting new connections - otherwise a request can still be routed
// here after Shutdown has begun.
const drainDelay = 5 * time.Second

// shutdownTimeout bounds how long Shutdown waits for in-flight requests
// (including open SSE streams and their underlying scans) to finish. It's
// intentionally generous - the real deadline is the Pod's
// terminationGracePeriodSeconds, which kubelet enforces with a SIGKILL
// regardless of what happens here.
const shutdownTimeout = 30 * time.Minute

//go:embed public/*
var staticEmbed embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory %s: %v", dataDir, err)
	}

	cfgMgr, err := config.NewManager(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize config manager: %v", err)
	}

	jobsMgr, err := jobs.NewManager(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize jobs manager: %v", err)
	}

	// Register scanner runner
	runner := scanner.NewRunner(cfgMgr, jobsMgr, dataDir)

	srv := server.NewServer(cfgMgr, jobsMgr, staticEmbed, runner.IsReady)

	addr := ":" + port
	httpSrv := &http.Server{Addr: addr, Handler: srv}

	log.Printf("🚢 Hullcheck Server (Go) starting on http://0.0.0.0:%s (Data Dir: %s)", port, dataDir)
	log.Printf("  ├─ Web UI: http://localhost:%s", port)
	log.Printf("  └─ Harbor Scanner Adapter: http://localhost:%s/api/v1/metadata", port)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server exited with error: %v", err)
		}
	case <-ctx.Done():
		stop()
		log.Printf("shutdown signal received: draining (readyz will fail for %s before we stop accepting connections)", drainDelay)
		srv.Drain()
		time.Sleep(drainDelay)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown did not complete cleanly: %v", err)
		}

		// Shutdown only waits for HTTP handlers, not the background scan
		// this pod may currently be running (CreateJob enqueues and
		// returns immediately) - wait for it too, or it gets killed
		// mid-run when the process exits.
		log.Printf("waiting for any in-flight scan on this pod to finish...")
		jobsMgr.WaitIdle(shutdownCtx)
		log.Printf("shutdown complete")
	}
}
