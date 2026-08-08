package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mariusbertram/anchor-webui/pkg/config"
	"github.com/mariusbertram/anchor-webui/pkg/jobs"
)

// testPkgTypeAPK / testSeverityKey are shared literals used across the
// fixture data below (syft artifact type, grype match severity key).
const (
	testPkgTypeAPK   = "apk"
	testSeverityKey  = "severity"
	testTypeKey      = "type"
	testVulnFieldKey = "vulnerability"
)

func TestSummarizeSyft(t *testing.T) {
	tmpDir := t.TempDir()
	sbomFile := filepath.Join(tmpDir, "sbom.json")

	content := map[string]interface{}{
		"artifacts": []map[string]interface{}{
			{testTypeKey: testPkgTypeAPK},
			{testTypeKey: testPkgTypeAPK},
			{testTypeKey: "npm"},
		},
		"distro": map[string]interface{}{
			"prettyName": "Alpine Linux",
			"versionID":  "3.20",
		},
	}
	data, _ := json.Marshal(content)
	_ = os.WriteFile(sbomFile, data, 0644)

	cfgMgr, _ := config.NewManager(tmpDir)
	jobsMgr, _ := jobs.NewManager(tmpDir)
	r := NewRunner(cfgMgr, jobsMgr, tmpDir)

	summary := r.summarizeSyft(sbomFile)
	if summary == nil {
		t.Fatalf("expected summary, got nil")
	}
	if summary.PackageCount != 3 {
		t.Errorf("expected 3 packages, got %d", summary.PackageCount)
	}
	if summary.ByType[testPkgTypeAPK] != 2 || summary.ByType["npm"] != 1 {
		t.Errorf("unexpected byType counts: %+v", summary.ByType)
	}
	if summary.Distro != "Alpine Linux 3.20" {
		t.Errorf("expected 'Alpine Linux 3.20', got '%s'", summary.Distro)
	}
}

func TestSummarizeGrype(t *testing.T) {
	tmpDir := t.TempDir()
	grypeFile := filepath.Join(tmpDir, "grype.json")

	content := map[string]interface{}{
		"matches": []map[string]interface{}{
			{testVulnFieldKey: map[string]interface{}{testSeverityKey: "Critical"}},
			{testVulnFieldKey: map[string]interface{}{testSeverityKey: "High"}},
			{testVulnFieldKey: map[string]interface{}{testSeverityKey: "High"}},
		},
	}
	data, _ := json.Marshal(content)
	_ = os.WriteFile(grypeFile, data, 0644)

	cfgMgr, _ := config.NewManager(tmpDir)
	jobsMgr, _ := jobs.NewManager(tmpDir)
	r := NewRunner(cfgMgr, jobsMgr, tmpDir)

	summary := r.summarizeGrype(grypeFile)
	if summary == nil {
		t.Fatalf("expected summary, got nil")
	}
	if summary.Total != 3 {
		t.Errorf("expected 3 total, got %d", summary.Total)
	}
	expectedBySev := map[string]int{"critical": 1, "high": 2}
	if !reflect.DeepEqual(summary.BySeverity, expectedBySev) {
		t.Errorf("expected %+v, got %+v", expectedBySev, summary.BySeverity)
	}
}

func TestSummarizeGrant(t *testing.T) {
	tmpDir := t.TempDir()
	grantFile := filepath.Join(tmpDir, "grant.json")

	// This is the fixed shape runLicenseSummary always writes - see
	// licensedPackage - not the real `grant` CLI's variable JSON shape.
	content := []licensedPackage{
		{Name: "pkg-a", Version: "1.0", Type: testPkgTypeAPK, Licenses: []string{"MIT"}},
		{Name: "pkg-b", Version: "2.0", Type: testPkgTypeAPK, Licenses: []string{"MIT"}},
		{Name: "pkg-c", Version: "3.0", Type: testPkgTypeAPK, Licenses: []string{"Apache-2.0"}},
		{Name: "pkg-d", Version: "4.0", Type: testPkgTypeAPK, Licenses: nil},
	}
	data, _ := json.Marshal(content)
	_ = os.WriteFile(grantFile, data, 0644)

	cfgMgr, _ := config.NewManager(tmpDir)
	jobsMgr, _ := jobs.NewManager(tmpDir)
	r := NewRunner(cfgMgr, jobsMgr, tmpDir)

	summary := r.summarizeGrant(grantFile)
	if summary == nil {
		t.Fatalf("expected summary, got nil")
	}
	if summary.PackageCount != 4 {
		t.Errorf("expected 4 packages, got %d", summary.PackageCount)
	}
	if summary.WithoutLicense != 1 {
		t.Errorf("expected 1 package without a license, got %d", summary.WithoutLicense)
	}
	if summary.LicenseCounts["MIT"] != 2 || summary.LicenseCounts["Apache-2.0"] != 1 {
		t.Errorf("unexpected license counts: %+v", summary.LicenseCounts)
	}
}
