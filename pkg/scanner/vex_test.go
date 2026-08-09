package scanner

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// realDSSEDigest is the sha256 digest of
// ghcr.io/mariusbertram/oc-mirror-operator-controller:v0.0.41 at the time
// testdata/dsse-openvex-real.json was captured (a real DSSE envelope pulled
// straight off ghcr.io - see fetchVEXDocuments's doc comment for the
// convention). The fixture's subject digest must match this exactly for
// extractVEXPredicate to accept it.
const (
	realDSSEDigestHex = "0f7fdb89ff465108427c7bc8871291a39100336ed5d95cbaf20915cce511759b"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return raw
}

func TestExtractVEXPredicateRealFixture(t *testing.T) {
	raw := readFixture(t, "dsse-openvex-real.json")

	predicate, ok := extractVEXPredicate(raw, "sha256", realDSSEDigestHex)
	if !ok {
		t.Fatal("expected the real fixture to be accepted as an OpenVEX predicate")
	}

	var doc struct {
		Context    string `json:"@context"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status string `json:"status"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(predicate, &doc); err != nil {
		t.Fatalf("extracted predicate isn't valid JSON: %v", err)
	}
	if doc.Context == "" {
		t.Error("extracted predicate is missing @context - doesn't look like a standalone OpenVEX document")
	}

	wantCVEs := map[string]bool{
		"CVE-2026-53492": false,
		"CVE-2026-50195": false,
		"CVE-2026-53489": false,
		"GO-2026-5932":   false,
	}
	for _, s := range doc.Statements {
		if _, tracked := wantCVEs[s.Vulnerability.Name]; tracked {
			wantCVEs[s.Vulnerability.Name] = true
		}
		if s.Status != "not_affected" {
			t.Errorf("statement for %s: got status %q, want not_affected", s.Vulnerability.Name, s.Status)
		}
	}
	for cve, found := range wantCVEs {
		if !found {
			t.Errorf("expected statement for %s in extracted predicate, not found", cve)
		}
	}
}

func TestExtractVEXPredicateWrongDigestRejected(t *testing.T) {
	raw := readFixture(t, "dsse-openvex-real.json")

	// A different (wrong) image digest - simulates the ".att" tag existing
	// but describing a different manifest than the one actually scanned.
	_, ok := extractVEXPredicate(raw, "sha256", "0000000000000000000000000000000000000000000000000000000000000000")
	if ok {
		t.Fatal("expected extractVEXPredicate to reject a subject digest mismatch, but it accepted the document")
	}
}

func TestExtractVEXPredicateWrongAlgorithmRejected(t *testing.T) {
	raw := readFixture(t, "dsse-openvex-real.json")

	// Right hex, wrong algorithm key - must not match on hex string alone.
	_, ok := extractVEXPredicate(raw, "sha512", realDSSEDigestHex)
	if ok {
		t.Fatal("expected extractVEXPredicate to reject a digest algorithm mismatch, but it accepted the document")
	}
}

func TestExtractVEXPredicateNonVEXPredicateTypeRejected(t *testing.T) {
	env := `{"payloadType":"application/vnd.in-toto+json","payload":"` +
		toBase64(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"x","digest":{"sha256":"`+realDSSEDigestHex+`"}}],"predicate":{}}`) +
		`"}`

	_, ok := extractVEXPredicate([]byte(env), "sha256", realDSSEDigestHex)
	if ok {
		t.Fatal("expected extractVEXPredicate to reject a non-OpenVEX predicateType (e.g. the SBOM attestation on the same tag), but it accepted the document")
	}
}

func TestExtractVEXPredicateMalformedInputRejected(t *testing.T) {
	cases := map[string]string{
		"not json at all": `not json`,
		"bad base64":      `{"payloadType":"x","payload":"not-base64!!!"}`,
		"base64 non-json": `{"payloadType":"x","payload":"` + toBase64("not json") + `"}`,
		"empty envelope":  `{}`,
		"empty predicate": `{"payloadType":"x","payload":"` + toBase64(`{}`) + `"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := extractVEXPredicate([]byte(raw), "sha256", realDSSEDigestHex); ok {
				t.Errorf("expected malformed input (%s) to be rejected, but it was accepted", name)
			}
		})
	}
}

func toBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
