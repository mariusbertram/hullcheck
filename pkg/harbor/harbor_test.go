package harbor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mariusbertram/anchor-webui/pkg/jobs"
)

func TestHarborMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	req := httptest.NewRequest("GET", "/api/v1/metadata", nil)
	rec := httptest.NewRecorder()

	handler.GetMetadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var meta Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if meta.Scanner.Name != "Anchor" {
		t.Errorf("expected scanner name 'Anchor', got '%s'", meta.Scanner.Name)
	}
}

func TestHarborAcceptScan(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	body := `{"artifact": {"repository": "library/alpine", "tag": "3.20"}}`
	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.AcceptScan(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", rec.Code)
	}

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.ID == "" {
		t.Errorf("expected non-empty scan request ID")
	}

	// CreateJob queues the scan onto a background worker; wait for it to
	// finish writing job files before the test's t.TempDir() is removed.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job := jobsMgr.GetJob(res.ID)
		if job != nil && (job.Status == "completed" || job.Status == "failed") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %s did not finish in time", res.ID)
}
