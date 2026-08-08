// Package validate guards against malformed or malicious image / OCI
// artifact references before they are ever passed to syft/grype/grant.
package validate

import "regexp"

var imageRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,510}$`)

// IsValidImageRef reports whether image looks like a plausible container
// image or OCI artifact reference. It never accepts whitespace or shell
// metacharacters, so it's safe to pass through as a single argv element.
func IsValidImageRef(image string) bool {
	return image != "" && imageRefRe.MatchString(image)
}
