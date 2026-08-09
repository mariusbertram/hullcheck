package harbor

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mariusbertram/hullcheck/pkg/jobs"
	"github.com/mariusbertram/hullcheck/pkg/validate"
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
		// Insecure indicates the registry is served over plain HTTP, not
		// HTTPS ("an indicator of https or http", per Harbor's own
		// pkg/scan/rest/v1/models.go) - not a TLS-cert-verification toggle.
		Insecure bool `json:"insecure"`
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
const scannerName = "Hullcheck"

type Handler struct {
	jobsMgr *jobs.Manager
}

// writeError responds with the Pluggable Scanner Spec's error shape
// ({"error": {"message": "..."}}, a nested object) - Harbor's own scan job
// unmarshals every non-2xx response body into that exact struct, and fails
// with an opaque "cannot unmarshal string into Go struct field
// ErrorResponse.error" (masking the real message) if given a bare string
// instead.
func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/vnd.scanner.adapter.error; version=1.0")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"message": message},
	})
}

func NewHandler(jobsMgr *jobs.Manager) *Handler {
	return &Handler{jobsMgr: jobsMgr}
}

func (h *Handler) GetMetadata(w http.ResponseWriter, r *http.Request) {
	meta := Metadata{
		Scanner: ScannerInfo{
			Name:    scannerName,
			Vendor:  "Hullcheck",
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
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// req.Artifact.Repository is bare ("library/foo", no host) - the
	// registry to pull from is only conveyed via req.Registry.URL. Without
	// prefixing it here, syft falls back to resolving the reference against
	// Docker Hub, which either fails outright (private/internal-only images)
	// or - worse - silently scans an unrelated public image that happens to
	// share the same repository path and tag.
	//
	// The scheme on req.Registry.URL is the reliable signal for whether the
	// registry is plain HTTP, not req.Registry.Insecure: Harbor's own
	// launchScanJob (src/controller/scan/base_controller.go) builds
	// v1.Registry{URL: registryAddr} without ever setting Insecure, so it's
	// always false in practice, on both the internal- and external-address
	// paths - even when registryAddr itself is an "http://" URL, as it will
	// be for any Harbor installation with expose.tls.enabled: false.
	insecureHTTP := strings.HasPrefix(req.Registry.URL, "http://") || req.Registry.Insecure
	registryHost := strings.TrimPrefix(strings.TrimPrefix(req.Registry.URL, "https://"), "http://")

	imageRef := req.Artifact.Repository
	if registryHost != "" {
		imageRef = registryHost + "/" + imageRef
	}
	if req.Artifact.Tag != "" {
		imageRef += ":" + req.Artifact.Tag
	} else if req.Artifact.Digest != "" {
		imageRef += "@" + req.Artifact.Digest
	}

	if !validate.IsValidImageRef(imageRef) {
		writeError(w, http.StatusBadRequest, "invalid artifact repository/tag/digest")
		return
	}

	regAuth := parseRegistryAuth(registryHost, req.Registry.Authorization)

	job := h.jobsMgr.CreateJob(imageRef, regAuth, false, insecureHTTP)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ScanResponse{ID: job.ID})
}

// regAuthAuthorityKey is the map key parseRegistryAuth uses for the
// registry host, matching what scanner.RunScan expects in the regAuth map
// CreateJob passes through.
const regAuthAuthorityKey = "authority"

// parseRegistryAuth turns Harbor's ready-to-use Authorization header value
// ("Bearer <token>" or "Basic <base64(user:pass)>", per Harbor's own
// pkg/scan/job.go) into the authority/username/password/token shape
// jobs.Manager passes through to config.Manager.BuildRegistryOptions, which
// wraps a bare token in its own "Bearer " prefix - passing the header value
// straight through as a token would double it up into "Bearer Bearer ...".
func parseRegistryAuth(authority, authorization string) map[string]string {
	switch {
	case strings.HasPrefix(authorization, "Bearer "):
		return map[string]string{
			regAuthAuthorityKey: authority,
			"token":             strings.TrimPrefix(authorization, "Bearer "),
		}
	case strings.HasPrefix(authorization, "Basic "):
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
		if err != nil {
			return nil
		}
		if idx := strings.IndexByte(string(decoded), ':'); idx != -1 {
			return map[string]string{
				regAuthAuthorityKey: authority,
				"username":          string(decoded[:idx]),
				"password":          string(decoded[idx+1:]),
			}
		}
	}
	return nil
}

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request, scanID string) {
	job := h.jobsMgr.GetJob(scanID)
	if job == nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}

	if job.Status == "queued" || job.Status == "running" {
		writeError(w, http.StatusFound, "scan still in progress")
		return
	}

	if job.Status == "failed" {
		msg := job.Error
		if msg == "" {
			msg = "scan failed"
		}
		writeError(w, http.StatusInternalServerError, msg)
		return
	}

	grypePath := h.jobsMgr.ArtifactPath(scanID, "grype.json")
	data, err := os.ReadFile(grypePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "grype report artifact not found")
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
				Vendor:  "Hullcheck",
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
