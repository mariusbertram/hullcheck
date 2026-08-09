package harbor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mariusbertram/hullcheck/pkg/jobs"
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

	if meta.Scanner.Name != scannerName {
		t.Errorf("expected scanner name 'Hullcheck', got '%s'", meta.Scanner.Name)
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

	waitForJobDone(t, jobsMgr, res.ID)
}

// waitForJobDone blocks until id reaches a terminal status. CreateJob queues
// the scan onto a background worker, so tests need this before returning -
// otherwise the worker can still be writing job files under t.TempDir() when
// the test cleans it up, racing "directory not empty" into the next test.
func waitForJobDone(t *testing.T, jobsMgr *jobs.Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job := jobsMgr.GetJob(id)
		if job != nil && (job.Status == "completed" || job.Status == "failed") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %s did not finish in time", id)
}

// TestHarborAcceptScanPrefixesRegistryHost guards against a regression where
// the scanned image reference was built from artifact.repository alone
// ("library/alpine:3.20", no host). Harbor's own registry is only conveyed
// via registry.url, so without prefixing it, syft resolved the reference
// against Docker Hub instead of the registry Harbor actually asked for -
// failing outright for private images, or silently scanning the wrong
// (coincidentally same-named) public image otherwise.
func TestHarborAcceptScanPrefixesRegistryHost(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	body := `{"registry": {"url": "http://harbor-core:80"}, "artifact": {"repository": "library/alpine", "tag": "3.20"}}`
	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.AcceptScan(rec, req)

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	job := jobsMgr.GetJob(res.ID)
	if job == nil {
		t.Fatalf("expected job %s to exist", res.ID)
	}
	const want = "harbor-core:80/library/alpine:3.20"
	if job.Image != want {
		t.Errorf("expected image ref %q, got %q", want, job.Image)
	}

	waitForJobDone(t, jobsMgr, res.ID)
}

// TestHarborAcceptScanDetectsHTTPFromURLScheme guards against a regression
// where InsecureUseHTTP was driven solely by registry.insecure. In real
// Harbor deployments that field is never actually set: launchScanJob
// (src/controller/scan/base_controller.go) builds v1.Registry{URL:
// registryAddr} without touching Insecure, so it's always false - even
// when registryAddr is itself an "http://" URL, which it will be for any
// Harbor installation with expose.tls.enabled: false (or any internal-
// address scanner deployment, since Harbor's own internal traffic is
// plain HTTP). Relying on registry.insecure alone meant every such Harbor
// install failed every scan with "server gave HTTP response to HTTPS
// client", regardless of what Harbor told the scanner.
func TestHarborAcceptScanDetectsHTTPFromURLScheme(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	// insecure deliberately omitted (defaults to false/zero value) - this
	// is exactly what real Harbor sends.
	body := `{"registry": {"url": "http://harbor-core:80"}, "artifact": {"repository": "library/alpine", "tag": "3.20"}}`
	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.AcceptScan(rec, req)

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	job := jobsMgr.GetJob(res.ID)
	if job == nil {
		t.Fatalf("expected job %s to exist", res.ID)
	}
	if !job.Options.InsecureUseHTTP {
		t.Errorf("expected InsecureUseHTTP to be true for an http:// registry URL, even with registry.insecure omitted")
	}

	waitForJobDone(t, jobsMgr, res.ID)
}

func TestParseRegistryAuth(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		got := parseRegistryAuth("harbor-core:80", "Bearer abc123")
		want := map[string]string{regAuthAuthorityKey: "harbor-core:80", "token": "abc123"}
		if got[regAuthAuthorityKey] != want[regAuthAuthorityKey] || got["token"] != want["token"] {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("basic", func(t *testing.T) {
		// base64("robot$scan:secret")
		got := parseRegistryAuth("harbor-core:80", "Basic cm9ib3Qkc2Nhbjpzc2VjcmV0")
		if got[regAuthAuthorityKey] != "harbor-core:80" || got["username"] != "robot$scan" || got["password"] != "ssecret" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("no double-wraps a bearer token that already has the scheme prefix", func(t *testing.T) {
		got := parseRegistryAuth("harbor-core:80", "Bearer abc123")
		if strings.Contains(got["token"], "Bearer") {
			t.Errorf("token should not contain the scheme prefix: %v", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := parseRegistryAuth("harbor-core:80", ""); got != nil {
			t.Errorf("expected nil for empty authorization, got %v", got)
		}
	})
}
