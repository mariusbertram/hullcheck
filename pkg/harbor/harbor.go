package harbor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/mariusbertram/anchor-webui/pkg/jobs"
	"github.com/mariusbertram/anchor-webui/pkg/validate"
)

type Metadata struct {
	Scanner      ScannerInfo  `json:"scanner"`
	Capabilities []Capability `json:"capabilities"`
}

type ScannerInfo struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

type ScanRequest struct {
	Registry struct {
		URL           string `json:"url"`
		Authorization string `json:"authorization"`
	} `json:"registry"`
	Artifact struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
		MimeType   string `json:"mime_type"`
	} `json:"artifact"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Links       []string `json:"links,omitempty"`
}

type VulnerabilityReport struct {
	GeneratedAt string              `json:"generated_at"`
	Artifact    ArtifactInfo        `json:"artifact"`
	Scanner     ScannerInfo         `json:"scanner"`
	Severity    string              `json:"severity"`
	Vulns       []VulnerabilityItem `json:"vulnerabilities"`
}

type ArtifactInfo struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag"`
}

// scannerName is the Harbor scanner adapter's advertised name, reused in
// both the metadata endpoint and the vulnerability report's scanner block.
const scannerName = "Anchor"

type Handler struct {
	jobsMgr *jobs.Manager
}

func NewHandler(jobsMgr *jobs.Manager) *Handler {
	return &Handler{jobsMgr: jobsMgr}
}

func (h *Handler) GetMetadata(w http.ResponseWriter, r *http.Request) {
	meta := Metadata{
		Scanner: ScannerInfo{
			Name:    scannerName,
			Vendor:  "Anchor WebUI",
			Version: "v1.0.0",
		},
		Capabilities: []Capability{
			{
				ConsumesMimeTypes: []string{
					"application/vnd.docker.distribution.manifest.v2+json",
					"application/vnd.oci.image.manifest.v1+json",
				},
				ProducesMimeTypes: []string{
					"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
					"application/vnd.security.vulnerability.report; version=1.1",
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (h *Handler) AcceptScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	imageRef := req.Artifact.Repository
	if req.Artifact.Tag != "" {
		imageRef += ":" + req.Artifact.Tag
	} else if req.Artifact.Digest != "" {
		imageRef += "@" + req.Artifact.Digest
	}

	if !validate.IsValidImageRef(imageRef) {
		http.Error(w, `{"error": "invalid artifact repository/tag/digest"}`, http.StatusBadRequest)
		return
	}

	var regAuth map[string]string
	if req.Registry.Authorization != "" {
		regAuth = map[string]string{
			"authority": req.Registry.URL,
			"token":     req.Registry.Authorization,
		}
	}

	job := h.jobsMgr.CreateJob(imageRef, regAuth, false, false)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ScanResponse{ID: job.ID})
}

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request, scanID string) {
	job := h.jobsMgr.GetJob(scanID)
	if job == nil {
		http.Error(w, `{"error": "scan job not found"}`, http.StatusNotFound)
		return
	}

	if job.Status == "queued" || job.Status == "running" {
		http.Error(w, `{"error": "scan still in progress"}`, http.StatusFound)
		return
	}

	grypePath := h.jobsMgr.ArtifactPath(scanID, "grype.json")
	data, err := os.ReadFile(grypePath)
	if err != nil {
		http.Error(w, `{"error": "grype report artifact not found"}`, http.StatusNotFound)
		return
	}

	var grypeDoc struct {
		Matches []struct {
			Vulnerability struct {
				ID          string   `json:"id"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				DataSource  string   `json:"dataSource"`
				URLs        []string `json:"urls"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	_ = json.Unmarshal(data, &grypeDoc)

	highestSev := severityUnknown
	sevOrder := map[string]int{severityCritical: 5, severityHigh: 4, severityMedium: 3, severityLow: 2, severityNegligible: 1, severityUnknown: 0}

	vulns := make([]VulnerabilityItem, 0, len(grypeDoc.Matches))
	for _, m := range grypeDoc.Matches {
		sev := capitalize(m.Vulnerability.Severity)
		if sevOrder[sev] > sevOrder[highestSev] {
			highestSev = sev
		}
		fixVer := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVer = m.Vulnerability.Fix.Versions[0]
		}
		vulns = append(vulns, VulnerabilityItem{
			ID:          m.Vulnerability.ID,
			Pkg:         m.Artifact.Name,
			Version:     m.Artifact.Version,
			FixVersion:  fixVer,
			Severity:    sev,
			Description: m.Vulnerability.Description,
			Links:       m.Vulnerability.URLs,
		})
	}

	report := map[string]interface{}{
		"application/vnd.security.vulnerability.report; version=1.1": VulnerabilityReport{
			GeneratedAt: filepath.Base(grypePath),
			Artifact: ArtifactInfo{
				Repository: job.Image,
			},
			Scanner: ScannerInfo{
				Name:    scannerName,
				Vendor:  "Anchor WebUI",
				Version: "v1.0.0",
			},
			Severity: highestSev,
			Vulns:    vulns,
		},
	}

	w.Header().Set("Content-Type", "application/vnd.security.vulnerability.report; version=1.1")
	_ = json.NewEncoder(w).Encode(report)
}

const severityUnknown = "Unknown"
const severityCritical = "Critical"
const severityHigh = "High"
const severityMedium = "Medium"
const severityLow = "Low"
const severityNegligible = "Negligible"

func capitalize(s string) string {
	if len(s) == 0 {
		return severityUnknown
	}
	switch s {
	case "critical", severityCritical:
		return severityCritical
	case "high", severityHigh:
		return severityHigh
	case "medium", severityMedium:
		return severityMedium
	case "low", severityLow:
		return severityLow
	case "negligible", severityNegligible:
		return severityNegligible
	default:
		return severityUnknown
	}
}
