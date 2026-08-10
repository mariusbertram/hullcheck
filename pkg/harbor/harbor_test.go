package harbor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mariusbertram/hullcheck/pkg/jobs"
)

const scanBodyAlpine = `{"artifact": {"repository": "library/alpine", "tag": "3.20"}}`

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

	var sawVuln, sawSBOM bool
	for _, c := range meta.Capabilities {
		switch c.Type {
		case scanTypeVulnerability:
			sawVuln = true
		case scanTypeSBOM:
			sawSBOM = true
			if len(c.ProducesMimeTypes) == 0 || c.ProducesMimeTypes[0] != mimeTypeSBOMReport {
				t.Errorf("expected sbom capability to produce %q, got %v", mimeTypeSBOMReport, c.ProducesMimeTypes)
			}
		}
	}
	if !sawVuln {
		t.Errorf("expected a %q capability", scanTypeVulnerability)
	}
	if !sawSBOM {
		t.Errorf("expected a %q capability", scanTypeSBOM)
	}
}

// TestHarborGetReportSBOM guards the SBOM report path added alongside the
// existing vulnerability report: Harbor requests it via
// Accept: application/vnd.security.sbom.report+json; version=1.0 (see
// Harbor's own GetScanReport in pkg/scan/rest/v1/client.go), and expects
// the response wrapped per src/pkg/scan/sbom/model.RawSBOMReport -
// generated_at/scanner/media_type alongside the SBOM content itself keyed
// under "sbom", not the raw SPDX document directly.
func TestHarborGetReportSBOM(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	body := scanBodyAlpine
	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.AcceptScan(rec, req)

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	waitForJobDone(t, jobsMgr, res.ID)

	// jobs.NewManager has no runner registered in tests, so no scanner ever
	// actually ran and wrote sbom-spdx.json - write a stand-in artifact the
	// same way scanner.runSyft would, to exercise getSBOMReport itself.
	spdxDoc := `{"spdxVersion": "SPDX-2.3", "name": "library/alpine:3.20"}`
	if err := os.WriteFile(jobsMgr.ArtifactPath(res.ID, "sbom-spdx.json"), []byte(spdxDoc), 0644); err != nil {
		t.Fatalf("failed to write stand-in spdx artifact: %v", err)
	}

	reportReq := httptest.NewRequest("GET", "/api/v1/scan/"+res.ID+"/report", nil)
	reportReq.Header.Set("Accept", mimeTypeSBOMReport)
	reportRec := httptest.NewRecorder()
	handler.GetReport(reportRec, reportReq, res.ID)

	if reportRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", reportRec.Code, reportRec.Body.String())
	}
	if ct := reportRec.Header().Get("Content-Type"); ct != mimeTypeSBOMReport {
		t.Errorf("expected Content-Type %q, got %q", mimeTypeSBOMReport, ct)
	}

	var envelope struct {
		GeneratedAt string                 `json:"generated_at"`
		Scanner     ScannerInfo            `json:"scanner"`
		MediaType   string                 `json:"media_type"`
		SBOM        map[string]interface{} `json:"sbom"`
	}
	if err := json.Unmarshal(reportRec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}
	if envelope.MediaType != mediaTypeSPDX {
		t.Errorf("expected media_type %q, got %q", mediaTypeSPDX, envelope.MediaType)
	}
	if envelope.Scanner.Name != scannerName {
		t.Errorf("expected scanner name %q, got %q", scannerName, envelope.Scanner.Name)
	}
	if envelope.SBOM["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected sbom content to be the parsed SPDX doc, got %v", envelope.SBOM)
	}
}

// TestHarborGetReportSBOMMissing guards the case where a scan predates SBOM
// support (or SPDX encoding failed) and sbom-spdx.json was never written -
// this must fail cleanly (a parseable error Harbor can surface), not with
// an unhandled panic or a body Harbor's client can't parse.
func TestHarborGetReportSBOMMissing(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	body := scanBodyAlpine
	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.AcceptScan(rec, req)

	var res ScanResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	waitForJobDone(t, jobsMgr, res.ID)

	reportReq := httptest.NewRequest("GET", "/api/v1/scan/"+res.ID+"/report", nil)
	reportReq.Header.Set("Accept", mimeTypeSBOMReport)
	reportRec := httptest.NewRecorder()
	handler.GetReport(reportRec, reportReq, res.ID)

	if reportRec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", reportRec.Code)
	}

	var errResp struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reportRec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("error body did not match the {error:{message}} shape Harbor expects: %v", err)
	}
	if errResp.Error.Message == "" {
		t.Errorf("expected a non-empty error message")
	}
}

// TestHarborGetReportVulnerabilityFallback guards the case where a scan
// predates precomputeHarborVulnReport (see pkg/scanner) - no
// grype-harbor.json artifact exists yet, only the raw grype.json a real
// scan would have written - and GetReport must still build the report on
// the fly from that.
func TestHarborGetReportVulnerabilityFallback(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(scanBodyAlpine))
	rec := httptest.NewRecorder()
	handler.AcceptScan(rec, req)

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	waitForJobDone(t, jobsMgr, res.ID)

	grypeDoc := `{"matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "High", "urls": ["https://example.com"]}, "artifact": {"name": "libfoo", "version": "1.0"}}]}`
	if err := os.WriteFile(jobsMgr.ArtifactPath(res.ID, "grype.json"), []byte(grypeDoc), 0644); err != nil {
		t.Fatalf("failed to write stand-in grype artifact: %v", err)
	}

	reportReq := httptest.NewRequest("GET", "/api/v1/scan/"+res.ID+"/report", nil)
	reportReq.Header.Set("Accept", mimeTypeVulnGeneric)
	reportRec := httptest.NewRecorder()
	handler.GetReport(reportRec, reportReq, res.ID)

	if reportRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", reportRec.Code, reportRec.Body.String())
	}

	var envelope map[string]VulnerabilityReport
	if err := json.Unmarshal(reportRec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}
	report, ok := envelope[mimeTypeVulnGeneric]
	if !ok || len(report.Vulns) != 1 || report.Vulns[0].ID != "CVE-2024-0001" {
		t.Fatalf("expected one CVE-2024-0001 finding, got %+v", envelope)
	}
	if report.Severity != severityHigh {
		t.Errorf("expected highest severity %q, got %q", severityHigh, report.Severity)
	}
}

// TestHarborGetReportVulnerabilityPrecomputed guards the fast path
// scanner.Runner's precomputeHarborVulnReport enables: when
// HarborVulnReportArtifact already exists, GetReport must serve it
// directly rather than re-deriving it from grype.json - which stays absent
// here on purpose, so a fallback to the slow path would fail the test.
func TestHarborGetReportVulnerabilityPrecomputed(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	req := httptest.NewRequest("POST", "/api/v1/scan", strings.NewReader(scanBodyAlpine))
	rec := httptest.NewRecorder()
	handler.AcceptScan(rec, req)

	var res ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	waitForJobDone(t, jobsMgr, res.ID)

	precomputed, err := EncodeVulnerabilityReport("library/alpine:3.20", time.Unix(0, 0), []byte(`{"matches": [{"vulnerability": {"id": "CVE-2024-9999", "severity": "Critical"}, "artifact": {"name": "libbar", "version": "2.0"}}]}`))
	if err != nil {
		t.Fatalf("EncodeVulnerabilityReport: %v", err)
	}
	if err := os.WriteFile(jobsMgr.ArtifactPath(res.ID, HarborVulnReportArtifact), precomputed, 0644); err != nil {
		t.Fatalf("failed to write precomputed artifact: %v", err)
	}
	// No grype.json written - if GetReport ever falls back to the slow
	// path here, it fails with "grype report artifact not found" instead
	// of silently passing.

	reportReq := httptest.NewRequest("GET", "/api/v1/scan/"+res.ID+"/report", nil)
	reportReq.Header.Set("Accept", mimeTypeVulnGeneric)
	reportRec := httptest.NewRecorder()
	handler.GetReport(reportRec, reportReq, res.ID)

	if reportRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", reportRec.Code, reportRec.Body.String())
	}
	if reportRec.Body.String() != string(precomputed) {
		t.Errorf("expected the precomputed artifact to be served byte-for-byte, got %s", reportRec.Body.String())
	}
}

func TestHarborAcceptScan(t *testing.T) {
	tmpDir := t.TempDir()
	jobsMgr, _ := jobs.NewManager(tmpDir)
	handler := NewHandler(jobsMgr)

	body := scanBodyAlpine
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
