package main

import (
	"context"
	"embed"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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

// staleTempDirAge is how old an orphaned scan temp directory (see
// setupScanTempDir) has to be before a fresh process startup removes it.
// It's set well above any realistic single scan's duration (bounded by
// ~2x TOOL_TIMEOUT_MS, ~30m by default) so a directory still in active use
// by a live scan - on this pod or a sibling sharing the same PVC - is never
// touched; only directories left behind by a hard-killed process (OOMKill,
// SIGKILL past terminationGracePeriodSeconds) ever get old enough to match.
const staleTempDirAge = 2 * time.Hour

//go:embed public/*
var staticEmbed embed.FS

// setupScanTempDir points TMPDIR at a directory under the PVC (dataDir)
// instead of the container's local/ephemeral root filesystem, and sweeps
// anything left over from a previous, crashed instance of this pod.
//
// syft's image pulling (via stereoscope, see pkg/scanner) and the VEX
// attestation lookup (pkg/scanner/vex.go) both extract a full copy of the
// scanned image's layers to os.TempDir() (== os.MkdirTemp("", ...), which
// honors $TMPDIR) while cataloging it, then delete it once the scan is
// done. Left pointed at the default /tmp, that's part of the container's
// own writable filesystem rather than the PVC - not shared across pods,
// not visible/manageable the way scan artifacts under DATA_DIR are, and
// prone to showing up as ballooning pod memory/page-cache usage over many
// scans since nothing ever evicts it the way a real ephemeral-storage
// volume would. Only set it if the operator hasn't already configured
// TMPDIR themselves (e.g. to a faster node-local disk).
func setupScanTempDir(dataDir string) {
	if os.Getenv("TMPDIR") != "" {
		return
	}
	tmpDir := filepath.Join(dataDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Fatalf("Failed to create scan temp directory %s: %v", tmpDir, err)
	}
	if err := os.Setenv("TMPDIR", tmpDir); err != nil {
		log.Fatalf("Failed to set TMPDIR: %v", err)
	}
	go cleanupStaleTempDirs(tmpDir)
}

// cleanupStaleTempDirs removes scan temp directories older than
// staleTempDirAge from a previous, crashed instance of this pod. Normal
// scans clean up after themselves (see pkg/scanner); this only catches the
// case a scan's own deferred cleanup never got to run at all (the process
// was SIGKILLed) - which matters now that TMPDIR lives on the PVC and no
// longer gets wiped for free by the container runtime on pod restart.
func cleanupStaleTempDirs(tmpDir string) {
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTempDirAge)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "stereoscope-") && !strings.HasPrefix(name, "hullcheck-vex-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(tmpDir, name)
		if err := os.RemoveAll(path); err != nil {
			log.Printf("startup: failed to remove stale scan temp dir %s: %v", path, err)
		} else {
			log.Printf("startup: removed stale scan temp dir %s (orphaned by a previous crash)", path)
		}
	}
}

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
	setupScanTempDir(dataDir)

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
