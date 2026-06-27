// Package version exposes build-time identification, populated via -ldflags.
package version

// These are overridden at build time, e.g.:
//
//	go build -ldflags="-X github.com/context-solutions-inc/secure-gateway/internal/version.Commit=$(git rev-parse HEAD)"
var (
	// Version is the semantic version of the build (e.g. "v0.1.0" or "dev").
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is the RFC3339 timestamp of the build.
	BuildDate = "unknown"
)

// String returns a human-readable build identifier.
func String() string {
	return Version + " (" + Commit + ", built " + BuildDate + ")"
}
