package validate

import "testing"

func TestIsValidImageRefAccepts(t *testing.T) {
	valid := []string{
		"alpine:latest",
		"docker.io/library/nginx:1.27",
		"registry.example.com:5000/team/app@sha256:" + repeat("a", 64),
		"ghcr.io/org/artifact:oci-1.0.0",
	}
	for _, image := range valid {
		if !IsValidImageRef(image) {
			t.Errorf("expected %q to be valid", image)
		}
	}
}

func TestIsValidImageRefRejects(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		" alpine:latest",
		"alpine latest",
		"image;rm -rf /",
		"$(whoami)",
		"`id`",
	}
	for _, image := range invalid {
		if IsValidImageRef(image) {
			t.Errorf("expected %q to be invalid", image)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
