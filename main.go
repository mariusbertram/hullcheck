package main

import (
	"embed"
	"log"
	"net/http"
	"os"

	"github.com/mariusbertram/anchor-webui/pkg/config"
	"github.com/mariusbertram/anchor-webui/pkg/jobs"
	"github.com/mariusbertram/anchor-webui/pkg/scanner"
	"github.com/mariusbertram/anchor-webui/pkg/server"
)

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
	log.Printf("⚓ Anchor Server (Go) starting on http://0.0.0.0:%s (Data Dir: %s)", port, dataDir)
	log.Printf("  ├─ Web UI: http://localhost:%s", port)
	log.Printf("  └─ Harbor Scanner Adapter: http://localhost:%s/api/v1/metadata", port)

	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}
