package harbor

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

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
	// Type is "vulnerability" or "sbom" (scanTypeVulnerability /
	// scanTypeSBOM below) - Harbor keys its supports_vulnerability /
	// supports_sbom flags off this per capability entry, per its own
	// pkg/scan/rest/v1/models.go.
	Type              string   `json:"type"`
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

const (
	scanTypeVulnerability = "vulnerability"
	scanTypeSBOM          = "sbom"

	mimeTypeVulnHarbor  = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeVulnGeneric = "application/vnd.security.vulnerability.report; version=1.1"
	mimeTypeSBOMReport  = "application/vnd.security.sbom.report+json; version=1.0"
	mediaTypeSPDX       = "application/spdx+json"
)

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

// scannerName/scannerVendor/scannerVersion are the Harbor scanner adapter's
// advertised identity, reused in the metadata endpoint and every report's
// scanner block (see scannerInfo).
const (
	scannerName    = "Hullcheck"
	scannerVendor  = "Hullcheck"
	scannerVersion = "v1.0.0"
)

func scannerInfo() ScannerInfo {
	return ScannerInfo{Name: scannerName, Vendor: scannerVendor, Version: scannerVersion}
}

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
		Scanner: scannerInfo(),
		Capabilities: []Capability{
			{
				Type: scanTypeVulnerability,
				ConsumesMimeTypes: []string{
					"application/vnd.docker.distribution.manifest.v2+json",
					"application/vnd.oci.image.manifest.v1+json",
				},
				ProducesMimeTypes: []string{
					mimeTypeVulnHarbor,
					mimeTypeVulnGeneric,
				},
			},
			{
				Type: scanTypeSBOM,
				ConsumesMimeTypes: []string{
					"application/vnd.docker.distribution.manifest.v2+json",
					"application/vnd.oci.image.manifest.v1+json",
				},
				ProducesMimeTypes: []string{
					mimeTypeSBOMReport,
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

// HarborVulnReportArtifact is the artifact name scanner.Runner precomputes
// this report under (see pkg/scanner) right after grype succeeds, so
// GetReport below can serve it as a plain file read instead of parsing and
// rebuilding it - potentially tens of thousands of entries for a CVE-heavy
// image - synchronously inside the request. Exported so pkg/scanner doesn't
// need to duplicate the filename.
const HarborVulnReportArtifact = "grype-harbor.json"

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

	if strings.Contains(r.Header.Get("Accept"), "sbom") {
		h.getSBOMReport(w, scanID, job)
		return
	}

	// The common case: scanner.Runner already built this report in the
	// background once grype finished (see precomputeHarborVulnReport), so
	// serving it is just a file read - no re-parsing a potentially huge
	// grype.json on Harbor's request path. Harbor starts polling GetReport
	// immediately after submitting the scan and gives up on a single call
	// after a short timeout; for an image with a CVE-heavy grype.json (tens
	// of MB isn't unusual for something like an OpenShift/RHCOS release
	// image), unmarshaling + rebuilding + re-marshaling it synchronously on
	// the very first poll after completion was slow enough to blow through
	// that timeout.
	precomputedPath := h.jobsMgr.ArtifactPath(scanID, HarborVulnReportArtifact)
	if data, err := os.ReadFile(precomputedPath); err == nil {
		w.Header().Set("Content-Type", mimeTypeVulnGeneric)
		_, _ = w.Write(data)
		return
	}

	// Fallback for scan history from before precomputation existed (no
	// grype-harbor.json artifact on disk) - build it on the fly like before.
	grypePath := h.jobsMgr.ArtifactPath(scanID, "grype.json")
	data, err := os.ReadFile(grypePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "grype report artifact not found")
		return
	}
	reportJSON, err := EncodeVulnerabilityReport(job.Image, time.Now(), data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "grype report artifact is not valid JSON")
		return
	}
	w.Header().Set("Content-Type", mimeTypeVulnGeneric)
	_, _ = w.Write(reportJSON)
}

// BuildVulnerabilityReport transforms grype's own JSON report (grypeData -
// the raw bytes of grype.json) into the shape GetReport serves under
// mimeTypeVulnGeneric.
func BuildVulnerabilityReport(image string, generatedAt time.Time, grypeData []byte) (VulnerabilityReport, error) {
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
	if err := json.Unmarshal(grypeData, &grypeDoc); err != nil {
		return VulnerabilityReport{}, err
	}

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

	return VulnerabilityReport{
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Artifact: ArtifactInfo{
			Repository: image,
		},
		Scanner:  scannerInfo(),
		Severity: highestSev,
		Vulns:    vulns,
	}, nil
}

// EncodeVulnerabilityReport marshals BuildVulnerabilityReport's result to
// bytes, ready to write straight to an HTTP response or, via
// scanner.Runner, to HarborVulnReportArtifact. Per the Pluggable Scanner
// Spec's OpenAPI schema (HarborVulnerabilityReport - both
// mimeTypeVulnGeneric and mimeTypeVulnHarbor use the exact same schema),
// the response body IS the report object at the top level - generated_at,
// artifact, scanner, severity, vulnerabilities as direct JSON keys - NOT
// wrapped in an object keyed by the mime type. An earlier version of this
// code wrapped it in exactly that (map[string]interface{}{mimeType:
// report}), which Harbor's own JSON decoder - expecting those fields at
// the top level - silently read as an all-zero-value report (no error, no
// crash, just severity "" and an empty vulnerabilities array) rather than
// failing loudly, so a scan that actually found vulnerabilities would show
// up in Harbor's UI as clean.
func EncodeVulnerabilityReport(image string, generatedAt time.Time, grypeData []byte) ([]byte, error) {
	report, err := BuildVulnerabilityReport(image, generatedAt, grypeData)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

// getSBOMReport serves the SPDX SBOM scanner.RunScan wrote alongside the
// native-format one, wrapped in the envelope Harbor's SBOM scan handler
// expects (src/pkg/scan/sbom/model.RawSBOMReport): generated_at, scanner,
// media_type, and the SBOM content itself keyed under "sbom".
func (h *Handler) getSBOMReport(w http.ResponseWriter, scanID string, job *jobs.Job) {
	spdxPath := h.jobsMgr.ArtifactPath(scanID, "sbom-spdx.json")
	data, err := os.ReadFile(spdxPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "spdx sbom artifact not found")
		return
	}

	var spdx map[string]interface{}
	if err := json.Unmarshal(data, &spdx); err != nil {
		writeError(w, http.StatusInternalServerError, "spdx sbom artifact is not valid JSON")
		return
	}

	generatedAt := ""
	if job.FinishedAt != nil {
		generatedAt = time.UnixMilli(*job.FinishedAt).UTC().Format(time.RFC3339)
	}

	report := map[string]interface{}{
		"generated_at": generatedAt,
		"scanner":      scannerInfo(),
		"media_type":   mediaTypeSPDX,
		"sbom":         spdx,
	}

	w.Header().Set("Content-Type", mimeTypeSBOMReport)
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
