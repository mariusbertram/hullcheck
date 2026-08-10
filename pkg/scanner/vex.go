package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/mariusbertram/hullcheck/pkg/jobs"
)

const (
	// dsseMediaType is the layer media type cosign (and compatible tools)
	// use for DSSE-enveloped in-toto attestations pushed to the
	// "sha256-<digest>.att" fallback tag - see fetchVEXDocuments.
	dsseMediaType = "application/vnd.dsse.envelope.v1+json"

	// openVexPredicatePrefix identifies an in-toto Statement's predicate as
	// an OpenVEX document (https://openvex.dev/ns, optionally versioned
	// e.g. "https://openvex.dev/ns/v0.2.0"). CSAF-format VEX attestations
	// aren't recognized yet - grype's own vex.Processor supports both, but
	// there's no equally well-established predicateType convention for CSAF
	// to match against here.
	openVexPredicatePrefix = "https://openvex.dev/ns"

	// vexFetchTimeout bounds the whole VEX-discovery round trip (digest
	// resolution + one manifest fetch + a handful of small blob fetches).
	// Kept short and separate from toolTimeout: this is a best-effort
	// enhancement layered on top of a scan that must otherwise complete
	// normally even if the registry is slow or doesn't support attestations
	// at all.
	vexFetchTimeout = 30 * time.Second

	// maxVexDocSize caps how much of a single attestation blob is read,
	// as a sanity bound against an unexpectedly huge attached document.
	maxVexDocSize = 10 * 1024 * 1024
)

// inTotoStatement is the subset of the in-toto Statement v0.1 format
// (https://in-toto.io/Statement/v0.1) needed to identify and extract a VEX
// predicate from a DSSE envelope's payload.
type inTotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Subject       []inTotoSubject `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubject struct {
	Digest map[string]string `json:"digest"`
}

// dsseEnvelope is the DSSE (Dead Simple Signing Envelope) shape wrapping the
// in-toto statement. Signatures are intentionally not verified here - see
// the "VEX attestations" entry under README's Known Limitations.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"` // base64-encoded inTotoStatement
}

type vexFetchResult struct {
	paths   []string
	cleanup func()
	err     error
}

// fetchVEXDocuments looks for OpenVEX attestations attached to imageRef via
// the same OCI convention cosign uses for SBOM/provenance attestations: a
// tag named "sha256-<image-digest>.att" in the same repository, holding an
// OCI manifest whose layers are DSSE-enveloped in-toto statements. Any layer
// whose decoded statement has predicateType "https://openvex.dev/ns..." and
// whose subject digest matches the resolved image digest is extracted to a
// temp file, ready for grype's vex.Processor.
//
// This deliberately does NOT verify the DSSE envelope's signature (that
// needs a trust policy - which signer identities/issuers are acceptable -
// which isn't configured anywhere in hullcheck today). The subject digest
// check only confirms the attestation is *about* the scanned image, not
// that it came from a trustworthy source: anyone able to push to the
// repository can push their own ".att" tag and suppress findings. See
// README's Known Limitations.
//
// Returns (nil, no-op cleanup, nil) whenever nothing usable is found -
// including the common case of no attestations at all - so the caller can
// treat "no VEX" and "lookup failed" alike as "scan proceeds without VEX".
func fetchVEXDocuments(ctx context.Context, imageRef string, regOpts image.RegistryOptions) ([]string, func(), error) {
	noop := func() {}

	fetchCtx, cancel := context.WithTimeout(ctx, vexFetchTimeout)
	defer cancel()

	var refOpts []name.Option
	if regOpts.InsecureUseHTTP {
		refOpts = append(refOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageRef, refOpts...)
	if err != nil {
		return nil, noop, fmt.Errorf("parsing image reference: %w", err)
	}

	opts, err := vexRemoteOptions(fetchCtx, ref, regOpts)
	if err != nil {
		return nil, noop, err
	}

	desc, err := remote.Head(ref, opts...)
	if err != nil {
		return nil, noop, fmt.Errorf("resolving image digest: %w", err)
	}

	attTag := ref.Context().Tag(strings.Replace(desc.Digest.String(), ":", "-", 1) + ".att")
	attDesc, err := remote.Get(attTag, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil, noop, nil
		}
		return nil, noop, fmt.Errorf("fetching attestation manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(attDesc.Manifest, &manifest); err != nil {
		return nil, noop, fmt.Errorf("parsing attestation manifest: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "hullcheck-vex-")
	if err != nil {
		return nil, noop, fmt.Errorf("creating temp dir for VEX documents: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	var docs []string
	for i, layer := range manifest.Layers {
		if layer.MediaType != dsseMediaType {
			continue
		}

		layerDigest := ref.Context().Digest(layer.Digest)
		blob, err := remote.Layer(layerDigest, opts...)
		if err != nil {
			continue // best-effort: skip this layer, keep looking at the rest
		}
		rc, err := blob.Compressed()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxVexDocSize))
		_ = rc.Close()
		if err != nil {
			continue
		}

		predicate, ok := extractVEXPredicate(raw, desc.Digest.Algorithm, desc.Digest.Hex)
		if !ok {
			continue // not a DSSE-wrapped OpenVEX statement about this image - skip silently
		}

		docPath := fmt.Sprintf("%s/vex-%d.json", tmpDir, i)
		if err := os.WriteFile(docPath, predicate, 0600); err != nil {
			continue
		}
		docs = append(docs, docPath)
	}

	if len(docs) == 0 {
		cleanup()
		return nil, noop, nil
	}
	return docs, cleanup, nil
}

// extractVEXPredicate decodes a raw DSSE-envelope blob (as fetched straight
// off the registry) into its wrapped in-toto statement and, if it's an
// OpenVEX predicate whose subject digest matches (algorithm, hex) - the
// resolved digest of the image actually being scanned - returns the raw
// predicate bytes (a standalone OpenVEX document, ready to write out for
// grype's vex.Processor). ok is false for anything else: malformed input,
// a non-VEX predicate (e.g. the SBOM/provenance attestation living on the
// same ".att" tag), or a VEX document whose subject is about a different
// image.
//
// The subject-digest check exists because the ".att" fallback tag is just a
// tag - nothing prevents it from existing for a different manifest digest
// than expected (multi-arch index vs. platform manifest) or from being
// pushed by any principal with registry write access. It confirms the
// attestation is *about* the scanned image; it does not confirm who wrote
// it - no signature verification is performed here at all (see the doc
// comment on fetchVEXDocuments).
func extractVEXPredicate(raw []byte, algorithm, hex string) (predicate []byte, ok bool) {
	var env dsseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, false
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, false
	}
	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, false
	}
	if !strings.HasPrefix(stmt.PredicateType, openVexPredicatePrefix) {
		return nil, false
	}
	if !subjectMatchesDigest(stmt.Subject, algorithm, hex) {
		return nil, false
	}
	return stmt.Predicate, true
}

func subjectMatchesDigest(subjects []inTotoSubject, algorithm, hex string) bool {
	for _, s := range subjects {
		if s.Digest[algorithm] == hex {
			return true
		}
	}
	return false
}

// vexRemoteOptions builds go-containerregistry remote.Options from the
// same image.RegistryOptions already resolved for the scan itself (mounted
// pull secret / UI-configured auths / per-scan override), so VEX discovery
// authenticates against the registry exactly like the syft/grype pull did -
// no separate credential resolution.
func vexRemoteOptions(ctx context.Context, ref name.Reference, regOpts image.RegistryOptions) ([]remote.Option, error) {
	registry := ref.Context().RegistryStr()

	opts := []remote.Option{remote.WithContext(ctx)}
	switch {
	case regOpts.Authenticator(registry) != nil:
		opts = append(opts, remote.WithAuth(regOpts.Authenticator(registry)))
	case regOpts.Keychain != nil:
		opts = append(opts, remote.WithAuthFromKeychain(regOpts.Keychain))
	default:
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	tlsCfg, err := regOpts.TLSConfig(registry)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}
	if tlsCfg != nil {
		// Clone remote.DefaultTransport rather than starting from a bare
		// &http.Transport{} - stereoscope's TLSConfig() always returns a
		// non-nil *tls.Config (even with nothing customized), so this runs
		// on every VEX lookup. A bare transport has Proxy: nil, silently
		// dropping HTTP_PROXY/HTTPS_PROXY support that the rest of the
		// registry client gets for free via DefaultTransport.
		t := remote.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = tlsCfg
		opts = append(opts, remote.WithTransport(t))
	}

	return opts, nil
}

// runVEXLookup wraps fetchVEXDocuments with job logging - failures and "no
// VEX found" both just mean the scan proceeds without VEX, so nothing here
// ever surfaces as a scan error.
func (r *Runner) runVEXLookup(ctx context.Context, job *jobs.Job, imageRef string, regOpts image.RegistryOptions) vexFetchResult {
	paths, cleanup, err := fetchVEXDocuments(ctx, imageRef, regOpts)
	if err != nil {
		r.jobsMgr.AppendLog(job.ID, "grype", "info", fmt.Sprintf("VEX attachment lookup skipped: %v", err))
	} else if len(paths) > 0 {
		r.jobsMgr.AppendLog(job.ID, "grype", "info", fmt.Sprintf("applying %d VEX document(s) attached to the image", len(paths)))
	}
	return vexFetchResult{paths: paths, cleanup: cleanup, err: err}
}
