package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/mariusbertram/hullcheck/pkg/config"
	"github.com/mariusbertram/hullcheck/pkg/jobs"
)

// appID identifies this binary to grype's DB distribution/installation
// clients (user agent, cache directory naming) - it never shells out to a
// syft/grype/grant CLI, everything runs through their Go libraries.
var appID = clio.Identification{Name: "hullcheck"}

func envBool(name string, def bool) bool {
	if v := os.Getenv(name); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

type Runner struct {
	cfgManager  *config.Manager
	jobsMgr     *jobs.Manager
	toolTimeout time.Duration

	// golangSearchRemoteLicenses enables syft's golang cataloger fetching
	// module licenses from a Go proxy (compiled Go binaries otherwise carry
	// almost no license metadata at all - see runSyft's doc comment). On by
	// default; air-gapped deployments with no reachable Go proxy should set
	// GOLANG_SEARCH_REMOTE_LICENSES=false (and/or point GOPROXY at an
	// internal Nexus mirror instead of disabling it outright).
	golangSearchRemoteLicenses bool

	// vexLookupEnabled controls whether each scan checks the registry for an
	// attached OpenVEX attestation (see vex.go) and, if found, feeds it into
	// grype's matching so vulnerabilities the vendor has marked
	// not_affected/fixed get suppressed. On by default - it's a bounded,
	// best-effort lookup against the same registry/credentials already used
	// for the scan, and failures never fail the scan. Disable
	// (VEX_LOOKUP_ENABLED=false) if you don't want unsigned VEX attestations
	// (no signature verification is performed - see README's Known
	// Limitations) to be able to influence scan results at all.
	vexLookupEnabled bool

	dbReady  chan struct{} // closed once a DB load attempt (success or failure) completes
	dbErr    string        // only written before dbReady is closed - safe to read after
	vulnProv vulnerability.Provider
	dbStatus *vulnerability.ProviderStatus
	matchers []match.Matcher
}

func NewRunner(cfgMgr *config.Manager, jobsMgr *jobs.Manager, dataDir string) *Runner {
	toolTimeout := 15 * time.Minute
	if v := os.Getenv("TOOL_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			toolTimeout = time.Duration(ms) * time.Millisecond
		}
	}
	golangSearchRemoteLicenses := envBool("GOLANG_SEARCH_REMOTE_LICENSES", true)
	vexLookupEnabled := envBool("VEX_LOOKUP_ENABLED", true)
	dbAutoUpdate := envBool("GRYPE_DB_AUTO_UPDATE", true)

	r := &Runner{
		cfgManager:                 cfgMgr,
		jobsMgr:                    jobsMgr,
		toolTimeout:                toolTimeout,
		golangSearchRemoteLicenses: golangSearchRemoteLicenses,
		vexLookupEnabled:           vexLookupEnabled,
		dbReady:                    make(chan struct{}),
	}

	jobsMgr.SetRunner(r.RunScan)
	log.Printf("scanner: runner ready (toolTimeout=%s, golangSearchRemoteLicenses=%t, vexLookupEnabled=%t), loading vulnerability database in background (autoUpdate=%t)",
		toolTimeout, golangSearchRemoteLicenses, vexLookupEnabled, dbAutoUpdate)
	go r.loadVulnerabilityDB(dataDir, dbAutoUpdate)
	return r
}

// loadVulnerabilityDB opens the grype vulnerability database once at
// startup, optionally checking for updates first (autoUpdate). The DB is
// cached under dataDir (the PVC) so it survives restarts and isn't
// re-downloaded per scan. For air-gapped clusters: pre-seed dataDir/grype-db
// (e.g. run this binary once somewhere with network access, pointed at the
// same DATA_DIR, then ship that directory) and set GRYPE_DB_AUTO_UPDATE=false
// so startup never depends on reaching the network - grype's own update
// check already fails soft (logs a warning and falls back to the on-disk DB)
// if the network is unreachable, but skipping it outright avoids even that
// bounded delay.
func (r *Runner) loadVulnerabilityDB(dataDir string, autoUpdate bool) {
	start := time.Now()

	distCfg := v6dist.DefaultConfig()
	distCfg.ID = appID

	instCfg := v6inst.DefaultConfig(appID)
	instCfg.DBRootDir = filepath.Join(dataDir, "grype-db")

	vp, status, err := grype.LoadVulnerabilityDB(distCfg, instCfg, autoUpdate)
	if err != nil {
		r.dbErr = err.Error()
		close(r.dbReady)
		log.Printf("scanner: FAILED to load vulnerability database: %v", err)
		return
	}

	r.vulnProv = vp
	r.dbStatus = status
	r.matchers = matcher.NewDefaultMatchers(matcher.Config{})
	close(r.dbReady)
	log.Printf("scanner: vulnerability database ready (schema=%s) in %s", status.SchemaVersion, time.Since(start).Round(time.Second))
}

// IsReady reports whether the vulnerability database finished loading
// successfully.
func (r *Runner) IsReady() bool {
	select {
	case <-r.dbReady:
		return r.dbErr == ""
	default:
		return false
	}
}

// waitForDB blocks until the vulnerability database is ready, the tool
// timeout elapses, or ctx is cancelled - whichever comes first.
func (r *Runner) waitForDB(ctx context.Context) error {
	select {
	case <-r.dbReady:
		if r.dbErr != "" {
			return fmt.Errorf("vulnerability database failed to load: %s", r.dbErr)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for the vulnerability database to load")
	}
}

func (r *Runner) RunScan(job *jobs.Job, regAuth map[string]string) {
	ctx := context.Background()

	var perScanAuth *config.RegistryAuth
	if regAuth != nil && regAuth["authority"] != "" {
		perScanAuth = &config.RegistryAuth{
			Authority: regAuth["authority"],
			Username:  regAuth["username"],
			Password:  regAuth["password"],
			Token:     regAuth["token"],
		}
	}

	registryOpts := r.cfgManager.BuildRegistryOptions(perScanAuth, job.Options.InsecureSkipTLSVerify, job.Options.InsecureUseHTTP)

	sbomPath := r.jobsMgr.ArtifactPath(job.ID, "sbom.json")
	sbomSpdxPath := r.jobsMgr.ArtifactPath(job.ID, "sbom-spdx.json")
	grypePath := r.jobsMgr.ArtifactPath(job.ID, "grype.json")
	grantPath := r.jobsMgr.ArtifactPath(job.ID, "grant.json")

	// Kicked off in parallel with syft below: VEX discovery only needs
	// job.Image + registryOpts, not the SBOM, and is a separate registry
	// round-trip worth overlapping with the (typically much longer) image
	// pull+catalog.
	vexCh := make(chan vexFetchResult, 1)
	if r.vexLookupEnabled {
		go func() { vexCh <- r.runVEXLookup(ctx, job, job.Image, registryOpts) }()
	} else {
		vexCh <- vexFetchResult{}
	}

	sbomObj, sbomJSON, syftOk := r.runSyft(ctx, job, registryOpts, sbomPath, sbomSpdxPath)
	if !syftOk {
		if vexRes := <-vexCh; vexRes.cleanup != nil {
			vexRes.cleanup()
		}
		r.jobsMgr.SetError(job.ID, "syft failed to build an SBOM - check the logs and image reference / registry credentials.")
		return
	}
	if syftSummary := r.summarizeSyft(sbomPath); syftSummary != nil {
		r.jobsMgr.SetSummary(job.ID, func(s *jobs.Summary) {
			s.Syft = syftSummary
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var grypeOk, grantOk bool

	go func() {
		defer wg.Done()
		vexRes := <-vexCh
		if vexRes.cleanup != nil {
			defer vexRes.cleanup()
		}
		grypeOk = r.runGrype(ctx, job, sbomJSON, grypePath, vexRes.paths)
		if grypeOk {
			if grypeSum := r.summarizeGrype(grypePath); grypeSum != nil {
				r.jobsMgr.SetSummary(job.ID, func(s *jobs.Summary) {
					s.Grype = grypeSum
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		grantOk = r.runLicenseSummary(job, sbomObj, grantPath)
		if grantOk {
			if grantSum := r.summarizeGrant(grantPath); grantSum != nil {
				r.jobsMgr.SetSummary(job.ID, func(s *jobs.Summary) {
					s.Grant = grantSum
				})
			}
		}
	}()

	wg.Wait()

	if !grypeOk && !grantOk {
		r.jobsMgr.SetError(job.ID, "vulnerability scan and license summary both failed - check the logs.")
	}
}

// runSyft catalogs job.Image via syft's library (no CLI, no PATH lookup) and
// writes the SBOM as syft's native JSON, which grype consumes downstream
// without re-pulling the registry, plus an SPDX JSON copy (spdxOutFile) for
// the Harbor Pluggable Scanner Adapter's SBOM report - Harbor's own SBOM
// tab expects application/spdx+json content, not syft's native format.
func (r *Runner) runSyft(ctx context.Context, job *jobs.Job, regOpts image.RegistryOptions, outFile, spdxOutFile string) (*sbom.SBOM, []byte, bool) {
	tool := "syft"
	r.jobsMgr.SetToolStatus(job.ID, tool, "running", nil)
	r.jobsMgr.AppendLog(job.ID, tool, "info", fmt.Sprintf("cataloging %s", job.Image))
	syft.SetLogger(newJobLogger(r.jobsMgr, job.ID, tool))

	toolCtx, cancel := context.WithTimeout(ctx, r.toolTimeout)
	defer cancel()

	fail := func(format string, args ...any) bool {
		msg := fmt.Sprintf(format, args...)
		r.jobsMgr.AppendLog(job.ID, tool, "stderr", msg)
		code := -1
		r.jobsMgr.SetToolStatus(job.ID, tool, "error", &code)
		return false
	}

	srcConfig := syft.DefaultGetSourceConfig().WithRegistryOptions(&regOpts)
	src, err := syft.GetSource(toolCtx, job.Image, srcConfig)
	if err != nil {
		return nil, nil, fail("GetSource error: %v", err)
	}

	sbomConfig := syft.DefaultCreateSBOMConfig()
	if r.golangSearchRemoteLicenses {
		// Compiled Go binaries carry almost no license metadata by default
		// (only module name+version via debug/buildinfo) - fetching from a
		// Go proxy is the only way syft finds real license data for them, so
		// this is on by default. NOTE: syft's remote license fetch uses a
		// bare http.Get with no request timeout and doesn't honor toolCtx -
		// on a network that silently drops packets rather than refusing
		// them, it can hang far longer than TOOL_TIMEOUT_MS. Air-gapped
		// clusters with no reachable Go proxy should set
		// GOLANG_SEARCH_REMOTE_LICENSES=false (or point GOPROXY at an
		// internal Nexus mirror, per the README's air-gapped section).
		r.jobsMgr.AppendLog(job.ID, tool, "info", "fetching go module licenses from the configured Go proxy")
		sbomConfig = sbomConfig.WithPackagesConfig(
			pkgcataloging.DefaultConfig().WithGolangConfig(
				golang.DefaultCatalogerConfig().WithSearchRemoteLicenses(true),
			),
		)
	}

	sbomObj, err := syft.CreateSBOM(toolCtx, src, sbomConfig)
	if err != nil {
		return nil, nil, fail("CreateSBOM error: %v", err)
	}

	encoder := syftjson.NewFormatEncoder()
	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *sbomObj); err != nil {
		return nil, nil, fail("json encode error: %v", err)
	}
	if err := os.WriteFile(outFile, buf.Bytes(), 0644); err != nil {
		return nil, nil, fail("failed to write %s: %v", outFile, err)
	}

	// SPDX export is a secondary output for Harbor's SBOM report (see
	// AcceptScan) - grype/grant only ever consume the native JSON above, so
	// a failure here shouldn't fail the scan, just leave the Harbor SBOM
	// report unavailable for this job.
	if spdxEncoder, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig()); err != nil {
		r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("spdx encoder init error: %v", err))
	} else {
		var spdxBuf bytes.Buffer
		if err := spdxEncoder.Encode(&spdxBuf, *sbomObj); err != nil {
			r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("spdx encode error: %v", err))
		} else if err := os.WriteFile(spdxOutFile, spdxBuf.Bytes(), 0644); err != nil {
			r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("failed to write %s: %v", spdxOutFile, err))
		}
	}

	exitCode := 0
	r.jobsMgr.AppendLog(job.ID, tool, "info", fmt.Sprintf("found %d packages", sbomObj.Artifacts.Packages.PackageCount()))
	r.jobsMgr.SetToolStatus(job.ID, tool, "success", &exitCode)
	return sbomObj, buf.Bytes(), true
}

// runGrype matches the already-built SBOM against grype's vulnerability
// database in-process (grype.VulnerabilityMatcher), writing the same JSON
// shape the `grype` CLI would. vexDocs (from fetchVEXDocuments, if any were
// found attached to the image) are applied via grype's own vex.Processor,
// which moves not_affected/fixed matches into the ignored list automatically
// as part of FindMatchesContext below.
func (r *Runner) runGrype(ctx context.Context, job *jobs.Job, sbomJSON []byte, outFile string, vexDocs []string) bool {
	tool := "grype"
	r.jobsMgr.SetToolStatus(job.ID, tool, "running", nil)

	toolCtx, cancel := context.WithTimeout(ctx, r.toolTimeout)
	defer cancel()

	fail := func(format string, args ...any) bool {
		msg := fmt.Sprintf(format, args...)
		r.jobsMgr.AppendLog(job.ID, tool, "stderr", msg)
		code := -1
		r.jobsMgr.SetToolStatus(job.ID, tool, "error", &code)
		return false
	}

	if err := r.waitForDB(toolCtx); err != nil {
		return fail("%v", err)
	}

	packages, pkgContext, _, err := grypepkg.ProvideFromReader(bytes.NewReader(sbomJSON), grypepkg.ProviderConfig{})
	if err != nil {
		return fail("failed to load SBOM for matching: %v", err)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: r.vulnProv,
		Matchers:              r.matchers,
	}
	if len(vexDocs) > 0 {
		vexProc, err := vex.NewProcessor(vex.ProcessorOptions{Documents: vexDocs})
		if err != nil {
			r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("VEX processor init failed, continuing without VEX: %v", err))
		} else {
			vulnMatcher.VexProcessor = vexProc
		}
	}

	matches, ignoredMatches, err := vulnMatcher.FindMatchesContext(toolCtx, packages, pkgContext)
	if err != nil || matches == nil {
		return fail("vulnerability matching failed: %v", err)
	}

	doc, err := models.NewDocument(
		appID, packages, pkgContext, *matches, ignoredMatches,
		r.vulnProv, nil, r.dbStatus,
		models.SortByPackage, false, nil,
	)
	if err != nil {
		return fail("failed to build report: %v", err)
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fail("failed to encode report: %v", err)
	}
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return fail("failed to write %s: %v", outFile, err)
	}

	exitCode := 0
	r.jobsMgr.AppendLog(job.ID, tool, "info", fmt.Sprintf("found %d vulnerability matches", matches.Count()))
	r.jobsMgr.SetToolStatus(job.ID, tool, "success", &exitCode)
	return true
}

type licensedPackage struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type,omitempty"`
	Licenses []string `json:"licenses"`
}

// extractLicenseNames mirrors what `grant list` reports for a package's
// licenses (github.com/anchore/grant/grant.ConvertSyftLicenses): compound
// SPDX expressions ("MIT AND BSD-2-Clause") are split into their individual
// license IDs via the same github.com/github/go-spdx/v2/spdxexp parser grant
// itself uses, duplicates are dropped, and the sha256:... content hashes
// syft emits as a license.Value when it can't identify a license are
// filtered out as noise.
//
// This reimplements that small piece of grant's logic instead of importing
// grant/grant directly: that package's case.go blank-imports
// modernc.org/sqlite (for RPM DB compat), which registers a "sqlite"
// database/sql driver under the same name grype's own DB v6 storage
// (github.com/glebarez/go-sqlite) already registers - the two collide with
// "sql: Register called twice for driver sqlite" the moment both are linked
// into one binary, which grype-as-library already requires.
func extractLicenseNames(set syftPkg.LicenseSet) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}

	for _, l := range set.ToSlice() {
		if l.SPDXExpression != "" {
			if extracted, err := spdxexp.ExtractLicenses(l.SPDXExpression); err == nil {
				for _, id := range extracted {
					add(strings.TrimRight(id, "+"))
				}
				continue
			}
			// unparsable expression: keep it as-is rather than dropping it
			add(l.SPDXExpression)
			continue
		}
		if strings.HasPrefix(l.Value, "sha256:") {
			continue
		}
		add(l.Value)
	}
	return names
}

// runLicenseSummary derives per-package license info directly from the
// already-built SBOM (syft catalogs license metadata as part of cataloging),
// so no separate license-discovery tool/library is needed at all.
func (r *Runner) runLicenseSummary(job *jobs.Job, sbomObj *sbom.SBOM, outFile string) bool {
	tool := "grant"
	r.jobsMgr.SetToolStatus(job.ID, tool, "running", nil)
	r.jobsMgr.AppendLog(job.ID, tool, "info", "deriving license summary from the SBOM")

	var out []licensedPackage
	for p := range sbomObj.Artifacts.Packages.Enumerate() {
		out = append(out, licensedPackage{
			Name:     p.Name,
			Version:  p.Version,
			Type:     string(p.Type),
			Licenses: extractLicenseNames(p.Licenses),
		})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("failed to encode license summary: %v", err))
		code := -1
		r.jobsMgr.SetToolStatus(job.ID, tool, "error", &code)
		return false
	}
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		r.jobsMgr.AppendLog(job.ID, tool, "stderr", fmt.Sprintf("failed to write %s: %v", outFile, err))
		code := -1
		r.jobsMgr.SetToolStatus(job.ID, tool, "error", &code)
		return false
	}

	exitCode := 0
	r.jobsMgr.AppendLog(job.ID, tool, "info", fmt.Sprintf("processed %d packages", len(out)))
	r.jobsMgr.SetToolStatus(job.ID, tool, "success", &exitCode)
	return true
}

func (r *Runner) summarizeSyft(path string) *jobs.SyftSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Artifacts []struct {
			Type string `json:"type"`
		} `json:"artifacts"`
		Distro struct {
			PrettyName string `json:"prettyName"`
			Name       string `json:"name"`
			ID         string `json:"id"`
			VersionID  string `json:"versionID"`
			Version    string `json:"version"`
		} `json:"distro"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}

	byType := make(map[string]int)
	for _, a := range doc.Artifacts {
		t := a.Type
		if t == "" {
			t = "unknown"
		}
		byType[t]++
	}

	distroStr := ""
	if doc.Distro.PrettyName != "" {
		distroStr = doc.Distro.PrettyName + " " + doc.Distro.VersionID
	} else if doc.Distro.Name != "" {
		distroStr = doc.Distro.Name + " " + doc.Distro.Version
	} else if doc.Distro.ID != "" {
		distroStr = doc.Distro.ID + " " + doc.Distro.VersionID
	}
	distroStr = strings.TrimSpace(distroStr)

	return &jobs.SyftSummary{
		PackageCount: len(doc.Artifacts),
		ByType:       byType,
		Distro:       distroStr,
	}
}

func (r *Runner) summarizeGrype(path string) *jobs.GrypeSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				Severity string `json:"severity"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}

	bySev := make(map[string]int)
	for _, m := range doc.Matches {
		sev := strings.ToLower(m.Vulnerability.Severity)
		if sev == "" {
			sev = "unknown"
		}
		bySev[sev]++
	}

	return &jobs.GrypeSummary{
		Total:      len(doc.Matches),
		BySeverity: bySev,
	}
}

// summarizeGrant reads the fixed []licensedPackage shape runLicenseSummary
// always writes (no shape-guessing needed - we're reading our own output,
// not the real `grant` CLI's variable JSON).
func (r *Runner) summarizeGrant(path string) *jobs.GrantSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var packages []licensedPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil
	}

	licenseCounts := make(map[string]int)
	withoutLicense := 0
	for _, pkg := range packages {
		if len(pkg.Licenses) == 0 {
			withoutLicense++
			continue
		}
		for _, l := range pkg.Licenses {
			licenseCounts[l]++
		}
	}

	return &jobs.GrantSummary{
		PackageCount:   len(packages),
		LicenseCounts:  licenseCounts,
		WithoutLicense: withoutLicense,
	}
}
